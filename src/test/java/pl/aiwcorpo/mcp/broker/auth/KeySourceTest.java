package pl.aiwcorpo.mcp.broker.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.MutableClock;
import pl.aiwcorpo.mcp.broker.support.TestTokens;

/** Unavailable key sources are an outage (503), not a bad token (401), and stale keys stop working. */
class KeySourceTest {

    @Test
    void gatewayKeysExpireWhenRefreshKeepsFailing() {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-27T12:00:00Z"));
        String jwks = Contracts.text(TestTokens.GATEWAY_JWKS_PATH);
        AtomicBoolean up = new AtomicBoolean(true);
        JwksGatewayKeys keys = new JwksGatewayKeys(() -> {
            if (!up.get()) {
                throw new IOException("down");
            }
            return jwks;
        }, "test", clock, Duration.ofMinutes(5), Duration.ofSeconds(10), Duration.ofHours(1));

        assertThat(keys.find("test-gw-2026-10-a")).isPresent();
        up.set(false);
        clock.advance(Duration.ofMinutes(30));
        assertThat(keys.find("test-gw-2026-10-a")).as("within max stale").isPresent();
        assertThat(keys.find("unknown")).isEmpty();
        clock.advance(Duration.ofMinutes(31));
        assertThatThrownBy(() -> keys.find("test-gw-2026-10-a")).isInstanceOf(KeySourceUnavailableException.class);
        up.set(true);
        clock.advance(Duration.ofSeconds(11));
        assertThat(keys.find("test-gw-2026-10-a")).isPresent();
    }

    @Test
    void lookupOnStaleKeysWaitsForTheRefreshInProgress() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-27T12:00:00Z"));
        String jwks = Contracts.text(TestTokens.GATEWAY_JWKS_PATH);
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch inFetch = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        JwksGatewayKeys keys = new JwksGatewayKeys(() -> {
            if (calls.incrementAndGet() > 1) {
                inFetch.countDown();
                if (!releaseFetch.await(10, TimeUnit.SECONDS)) {
                    throw new IOException("test timeout");
                }
            }
            return jwks;
        }, "test", clock, Duration.ofMinutes(5), Duration.ofSeconds(10), Duration.ofHours(1), Duration.ofSeconds(10));
        assertThat(keys.find("test-gw-2026-10-a")).isPresent();

        clock.advance(Duration.ofHours(2));
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<?> refreshing = pool.submit(() -> keys.find("test-gw-2026-10-a"));
            assertThat(inFetch.await(5, TimeUnit.SECONDS)).isTrue();
            Future<Boolean> concurrent = pool.submit(() -> keys.find("test-gw-2026-10-a").isPresent());
            Thread.sleep(200);
            assertThat(concurrent.isDone()).as("second lookup waits instead of failing").isFalse();
            releaseFetch.countDown();
            assertThat(concurrent.get(5, TimeUnit.SECONDS)).isTrue();
            refreshing.get(5, TimeUnit.SECONDS);
            assertThat(calls.get()).as("the waiter does not fetch again").isEqualTo(2);
        } finally {
            releaseFetch.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void lookupOnStaleKeysFailsClosedWhenTheRefreshFailsAndDoesNotRefetchWithinTheInterval() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-27T12:00:00Z"));
        String jwks = Contracts.text(TestTokens.GATEWAY_JWKS_PATH);
        AtomicBoolean up = new AtomicBoolean(true);
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch inFetch = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        JwksGatewayKeys keys = new JwksGatewayKeys(() -> {
            calls.incrementAndGet();
            if (!up.get()) {
                inFetch.countDown();
                releaseFetch.await(10, TimeUnit.SECONDS);
                throw new IOException("down");
            }
            return jwks;
        }, "test", clock, Duration.ofMinutes(5), Duration.ofSeconds(10), Duration.ofHours(1), Duration.ofSeconds(10));
        assertThat(keys.find("test-gw-2026-10-a")).isPresent();

        up.set(false);
        clock.advance(Duration.ofHours(2));
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<?> refreshing = pool.submit(() -> keys.find("test-gw-2026-10-a"));
            assertThat(inFetch.await(5, TimeUnit.SECONDS)).isTrue();
            Future<?> concurrent = pool.submit(() -> keys.find("test-gw-2026-10-a"));
            releaseFetch.countDown();
            assertThatThrownBy(() -> concurrent.get(5, TimeUnit.SECONDS)).hasCauseInstanceOf(KeySourceUnavailableException.class);
            assertThatThrownBy(() -> refreshing.get(5, TimeUnit.SECONDS)).hasCauseInstanceOf(KeySourceUnavailableException.class);
            assertThat(calls.get()).as("one failed fetch for both lookups").isEqualTo(2);
        } finally {
            releaseFetch.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void waiterGivesUpAfterTheLockWait() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-27T12:00:00Z"));
        String jwks = Contracts.text(TestTokens.GATEWAY_JWKS_PATH);
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch inFetch = new CountDownLatch(1);
        CountDownLatch releaseFetch = new CountDownLatch(1);
        JwksGatewayKeys keys = new JwksGatewayKeys(() -> {
            if (calls.incrementAndGet() > 1) {
                inFetch.countDown();
                releaseFetch.await(10, TimeUnit.SECONDS);
            }
            return jwks;
        }, "test", clock, Duration.ofMinutes(5), Duration.ofSeconds(10), Duration.ofHours(1), Duration.ofMillis(200));
        assertThat(keys.find("test-gw-2026-10-a")).isPresent();

        clock.advance(Duration.ofHours(2));
        ExecutorService pool = Executors.newFixedThreadPool(1);
        try {
            Future<?> refreshing = pool.submit(() -> keys.find("test-gw-2026-10-a"));
            assertThat(inFetch.await(5, TimeUnit.SECONDS)).isTrue();
            assertThatThrownBy(() -> keys.find("test-gw-2026-10-a")).isInstanceOf(KeySourceUnavailableException.class);
            releaseFetch.countDown();
            refreshing.get(5, TimeUnit.SECONDS);
        } finally {
            releaseFetch.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void gatewayKeysNeverLoadedAreUnavailable() {
        JwksGatewayKeys keys = new JwksGatewayKeys(() -> {
            throw new IOException("down");
        }, "test", new MutableClock(Instant.now()), Duration.ofMinutes(5), Duration.ofSeconds(10), Duration.ofHours(1));
        assertThatThrownBy(() -> keys.find("any")).isInstanceOf(KeySourceUnavailableException.class);
    }

    @Test
    void idpJwksOutageIsNotABadToken() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/jwks", exchange -> {
            exchange.sendResponseHeaders(500, -1);
            exchange.close();
        });
        server.start();
        try {
            BrokerProperties.BffToken config = new BrokerProperties.BffToken(TestTokens.IDP_ISSUER,
                    URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/jwks"), "mcp-credential-broker",
                    Set.of("mcp-portal-bff"), "preferred_username");
            BffTokenVerifier verifier = BffTokenVerifier.create(config, HttpClient.newHttpClient());
            String token = new TestTokens().bffUser("sub-1", "alice");
            assertThatThrownBy(() -> verifier.verify(token, "rid")).isInstanceOf(KeySourceUnavailableException.class);
        } finally {
            server.stop(0);
        }
    }
}
