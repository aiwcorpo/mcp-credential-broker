package pl.aiwcorpo.mcp.broker.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
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
        assertThatThrownBy(() -> keys.find("unknown")).as("an outage must not look like a bad kid")
                .isInstanceOf(KeySourceUnavailableException.class);
        clock.advance(Duration.ofMinutes(31));
        assertThatThrownBy(() -> keys.find("test-gw-2026-10-a")).isInstanceOf(KeySourceUnavailableException.class);
        up.set(true);
        clock.advance(Duration.ofSeconds(11));
        assertThat(keys.find("test-gw-2026-10-a")).isPresent();
    }

    private static final String KID_A = "test-gw-2026-10-a";
    private static final Instant T0 = Instant.parse("2026-10-27T12:00:00Z");

    /** Source whose second call is scripted by the test (blocks, optionally fails); every other call returns the full JWKS. */
    private static final class ScriptedSource implements Callable<String> {
        final String jwks = Contracts.text(TestTokens.GATEWAY_JWKS_PATH);
        final AtomicInteger calls = new AtomicInteger();
        final CountDownLatch inFetch = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        volatile Runnable duringFetch = () -> { };
        volatile boolean failAfterRelease;

        @Override
        public String call() throws Exception {
            if (calls.incrementAndGet() == 2) {
                duringFetch.run();
                inFetch.countDown();
                if (!release.await(10, TimeUnit.SECONDS)) {
                    throw new IOException("test timeout");
                }
                if (failAfterRelease) {
                    throw new IOException("down");
                }
            }
            return jwks;
        }
    }

    private static void awaitWaiter(JwksGatewayKeys keys) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!keys.hasWaitingThreads()) {
            assertThat(System.nanoTime()).as("a thread is queued on the refresh").isLessThan(deadline);
            Thread.onSpinWait();
        }
    }

    private static JwksGatewayKeys keysOver(Callable<String> source, MutableClock clock, Duration lockWait) {
        return new JwksGatewayKeys(source, "test", clock, Duration.ofMinutes(5), Duration.ofSeconds(10), Duration.ofHours(1),
                lockWait);
    }

    @Test
    void lookupOnStaleKeysWaitsForTheRefreshInProgress() throws Exception {
        MutableClock clock = new MutableClock(T0);
        ScriptedSource source = new ScriptedSource();
        // The fetch outlasts the minimum interval, as a slow endpoint would.
        source.duringFetch = () -> clock.advance(Duration.ofSeconds(11));
        JwksGatewayKeys keys = keysOver(source, clock, Duration.ofSeconds(10));
        assertThat(keys.find(KID_A)).isPresent();

        clock.advance(Duration.ofHours(2));
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<?> refreshing = pool.submit(() -> keys.find(KID_A));
            assertThat(source.inFetch.await(5, TimeUnit.SECONDS)).isTrue();
            Future<Boolean> concurrent = pool.submit(() -> keys.find(KID_A).isPresent());
            awaitWaiter(keys);
            assertThat(concurrent.isDone()).as("second lookup is parked on the refresh").isFalse();
            source.release.countDown();
            assertThat(concurrent.get(5, TimeUnit.SECONDS)).isTrue();
            refreshing.get(5, TimeUnit.SECONDS);
            assertThat(source.calls.get()).as("the waiter uses the result instead of fetching again").isEqualTo(2);
        } finally {
            source.release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void lookupOnStaleKeysFailsClosedWhenTheRefreshFailsAndDoesNotRefetchWithinTheInterval() throws Exception {
        MutableClock clock = new MutableClock(T0);
        ScriptedSource source = new ScriptedSource();
        source.failAfterRelease = true;
        JwksGatewayKeys keys = keysOver(source, clock, Duration.ofSeconds(10));
        assertThat(keys.find(KID_A)).isPresent();

        clock.advance(Duration.ofHours(2));
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<?> refreshing = pool.submit(() -> keys.find(KID_A));
            assertThat(source.inFetch.await(5, TimeUnit.SECONDS)).isTrue();
            Future<?> concurrent = pool.submit(() -> keys.find(KID_A));
            awaitWaiter(keys);
            source.release.countDown();
            assertThatThrownBy(() -> concurrent.get(5, TimeUnit.SECONDS)).hasCauseInstanceOf(KeySourceUnavailableException.class);
            assertThatThrownBy(() -> refreshing.get(5, TimeUnit.SECONDS)).hasCauseInstanceOf(KeySourceUnavailableException.class);
            assertThat(source.calls.get()).as("one failed fetch for both lookups").isEqualTo(2);
        } finally {
            source.release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void waiterRetriesWhenTheAttemptItWaitedForFailedAndTheIntervalHasPassed() throws Exception {
        MutableClock clock = new MutableClock(T0);
        ScriptedSource source = new ScriptedSource();
        source.failAfterRelease = true;
        JwksGatewayKeys keys = keysOver(source, clock, Duration.ofSeconds(10));
        assertThat(keys.find(KID_A)).isPresent();

        clock.advance(Duration.ofHours(2));
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<?> failing = pool.submit(() -> keys.find(KID_A));
            assertThat(source.inFetch.await(5, TimeUnit.SECONDS)).isTrue();
            Future<Boolean> waiter = pool.submit(() -> keys.find(KID_A).isPresent());
            awaitWaiter(keys);
            // The waiter began before this, so only a clock read after the wait lets it retry.
            clock.advance(Duration.ofSeconds(11));
            source.release.countDown();
            assertThatThrownBy(() -> failing.get(5, TimeUnit.SECONDS)).hasCauseInstanceOf(KeySourceUnavailableException.class);
            assertThat(waiter.get(5, TimeUnit.SECONDS)).as("the endpoint is back, the interval is judged after the wait").isTrue();
            assertThat(source.calls.get()).isEqualTo(3);
        } finally {
            source.release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void lookupThatStartedInsideMaxStaleIsNotFailedByARefreshAtTheBoundary() throws Exception {
        ScriptedClock clock = new ScriptedClock(T0);
        ScriptedSource source = new ScriptedSource();
        JwksGatewayKeys keys = new JwksGatewayKeys(source, "test", clock, Duration.ofMinutes(5), Duration.ofSeconds(10),
                Duration.ofHours(1), Duration.ofSeconds(10));
        assertThat(keys.find(KID_A)).isPresent();

        clock.set(T0.plus(Duration.ofHours(1)).plusSeconds(1));
        ExecutorService pool = Executors.newFixedThreadPool(1);
        try {
            Future<?> refreshing = pool.submit(() -> keys.find(KID_A));
            assertThat(source.inFetch.await(5, TimeUnit.SECONDS)).isTrue();
            clock.firstReadOfCurrentThread(T0.plus(Duration.ofMinutes(59)));
            assertThat(keys.find(KID_A)).as("started before the boundary, finished after it").isPresent();
            source.release.countDown();
            refreshing.get(5, TimeUnit.SECONDS);
        } finally {
            source.release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void unknownKidWaitsForTheRefreshInProgressAndFindsTheRotatedKey() throws Exception {
        MutableClock clock = new MutableClock(T0);
        ScriptedSource source = new ScriptedSource();
        String full = source.jwks;
        List<JWK> all = JWKSet.parse(full).getKeys();
        String rotatedKid = all.get(1).getKeyID();
        String onlyFirst = new JWKSet(all.get(0)).toString();
        AtomicInteger loads = new AtomicInteger();
        CountDownLatch inFetch = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        JwksGatewayKeys keys = keysOver(() -> {
            if (loads.incrementAndGet() == 1) {
                return onlyFirst;
            }
            inFetch.countDown();
            release.await(10, TimeUnit.SECONDS);
            return full;
        }, clock, Duration.ofSeconds(10));
        assertThat(keys.find(all.get(0).getKeyID())).isPresent();

        clock.advance(Duration.ofSeconds(11));
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> first = pool.submit(() -> keys.find(rotatedKid).isPresent());
            assertThat(inFetch.await(5, TimeUnit.SECONDS)).isTrue();
            Future<Boolean> second = pool.submit(() -> keys.find(rotatedKid).isPresent());
            awaitWaiter(keys);
            release.countDown();
            assertThat(first.get(5, TimeUnit.SECONDS)).isTrue();
            assertThat(second.get(5, TimeUnit.SECONDS)).as("not answered unknown_kid while the key was being loaded").isTrue();
            assertThat(loads.get()).isEqualTo(2);
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void waiterGivesUpAfterTheLockWait() throws Exception {
        MutableClock clock = new MutableClock(T0);
        ScriptedSource source = new ScriptedSource();
        JwksGatewayKeys keys = keysOver(source, clock, Duration.ofMillis(200));
        assertThat(keys.find(KID_A)).isPresent();

        clock.advance(Duration.ofHours(2));
        ExecutorService pool = Executors.newFixedThreadPool(1);
        try {
            Future<?> refreshing = pool.submit(() -> keys.find(KID_A));
            assertThat(source.inFetch.await(5, TimeUnit.SECONDS)).isTrue();
            assertThatThrownBy(() -> keys.find(KID_A)).isInstanceOf(KeySourceUnavailableException.class);
            source.release.countDown();
            refreshing.get(5, TimeUnit.SECONDS);
        } finally {
            source.release.countDown();
            pool.shutdownNow();
        }
    }

    /** Fresh keys, a kid they do not hold and a refresh that is blocked in the source. */
    private static void startBlockedRefreshOfUnknownKid(JwksGatewayKeys keys, MutableClock clock, ScriptedSource source,
            ExecutorService pool) throws InterruptedException {
        assertThat(keys.find(KID_A)).isPresent();
        clock.advance(Duration.ofSeconds(11));
        pool.submit(() -> keys.find("unknown-kid-1"));
        assertThat(source.inFetch.await(5, TimeUnit.SECONDS)).isTrue();
    }

    @Test
    void unknownKidOnFreshKeysIsUnavailableWhenTheWaitForTheRefreshRunsOut() throws Exception {
        MutableClock clock = new MutableClock(T0);
        ScriptedSource source = new ScriptedSource();
        JwksGatewayKeys keys = keysOver(source, clock, Duration.ofMillis(200));
        ExecutorService pool = Executors.newFixedThreadPool(1);
        try {
            startBlockedRefreshOfUnknownKid(keys, clock, source, pool);
            assertThatThrownBy(() -> keys.find("unknown-kid-2")).as("not an answer that the kid does not exist")
                    .isInstanceOf(KeySourceUnavailableException.class);
        } finally {
            source.release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void lookupsBeyondTheWaiterLimitFailAtOnceInsteadOfParkingThreads() throws Exception {
        MutableClock clock = new MutableClock(T0);
        ScriptedSource source = new ScriptedSource();
        JwksGatewayKeys keys = new JwksGatewayKeys(source, "test", clock, Duration.ofMinutes(5), Duration.ofSeconds(10),
                Duration.ofHours(1), Duration.ofSeconds(30), 1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            startBlockedRefreshOfUnknownKid(keys, clock, source, pool);
            Future<?> parked = pool.submit(() -> keys.find("unknown-kid-2"));
            awaitWaiter(keys);

            long started = System.nanoTime();
            assertThatThrownBy(() -> keys.find("unknown-kid-3")).isInstanceOf(KeySourceUnavailableException.class);
            assertThat(Duration.ofNanos(System.nanoTime() - started)).as("did not wait for the lock")
                    .isLessThan(Duration.ofSeconds(5));
            assertThat(parked.isDone()).as("the first waiter is still parked").isFalse();

            source.release.countDown();
            assertThat(parked.get(5, TimeUnit.SECONDS)).as("a fetch that succeeded rules the kid out").isEqualTo(java.util.Optional.empty());
        } finally {
            source.release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void aWaiterThatTimedOutReturnsItsSlotSoTheNextOneCanWaitToo() throws Exception {
        MutableClock clock = new MutableClock(T0);
        ScriptedSource source = new ScriptedSource();
        JwksGatewayKeys keys = new JwksGatewayKeys(source, "test", clock, Duration.ofMinutes(5), Duration.ofSeconds(10),
                Duration.ofHours(1), Duration.ofMillis(300), 1);
        ExecutorService pool = Executors.newFixedThreadPool(1);
        try {
            startBlockedRefreshOfUnknownKid(keys, clock, source, pool);
            for (int timedOut = 0; timedOut < 3; timedOut++) {
                long started = System.nanoTime();
                assertThatThrownBy(() -> keys.find("unknown-kid-2")).isInstanceOf(KeySourceUnavailableException.class);
                assertThat(Duration.ofNanos(System.nanoTime() - started)).as("waited %d, not refused for lack of a slot", timedOut)
                        .isGreaterThanOrEqualTo(Duration.ofMillis(250));
            }
        } finally {
            source.release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void emptyJwksIsAFailedRefreshAndKeepsTheKnownKeys() throws Exception {
        MutableClock clock = new MutableClock(T0);
        AtomicBoolean empty = new AtomicBoolean();
        String full = Contracts.text(TestTokens.GATEWAY_JWKS_PATH);
        JwksGatewayKeys keys = keysOver(() -> empty.get() ? "{\"keys\":[]}" : full, clock, Duration.ofSeconds(10));
        assertThat(keys.find(KID_A)).isPresent();

        empty.set(true);
        clock.advance(Duration.ofSeconds(11));
        assertThatThrownBy(() -> keys.find("unknown-kid-1")).as("not a 401 for a kid that cannot be ruled out")
                .isInstanceOf(KeySourceUnavailableException.class);
        assertThat(keys.find(KID_A)).as("the good keys are still there").isPresent();
    }

    @Test
    void interruptedWaiterFailsClosedAndKeepsTheInterrupt() throws Exception {
        MutableClock clock = new MutableClock(T0);
        ScriptedSource source = new ScriptedSource();
        JwksGatewayKeys keys = keysOver(source, clock, Duration.ofSeconds(30));
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            startBlockedRefreshOfUnknownKid(keys, clock, source, pool);
            AtomicBoolean interruptKept = new AtomicBoolean();
            java.util.concurrent.atomic.AtomicReference<Thread> waiterThread = new java.util.concurrent.atomic.AtomicReference<>();
            Future<Boolean> waiter = pool.submit(() -> {
                waiterThread.set(Thread.currentThread());
                try {
                    keys.find("unknown-kid-2");
                    return false;
                } catch (KeySourceUnavailableException e) {
                    interruptKept.set(Thread.currentThread().isInterrupted());
                    return true;
                }
            });
            awaitWaiter(keys);
            waiterThread.get().interrupt();
            assertThat(waiter.get(5, TimeUnit.SECONDS)).isTrue();
            assertThat(interruptKept.get()).isTrue();
        } finally {
            source.release.countDown();
            pool.shutdownNow();
        }
    }

    /** Clock that can answer the first read of one thread with a different time than every later read. */
    private static final class ScriptedClock extends Clock {
        private volatile Instant now;
        private volatile Thread scriptedThread;
        private volatile Instant scriptedFirst;

        ScriptedClock(Instant now) {
            this.now = now;
        }

        void set(Instant instant) {
            now = instant;
        }

        void firstReadOfCurrentThread(Instant instant) {
            scriptedThread = Thread.currentThread();
            scriptedFirst = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            if (Thread.currentThread() == scriptedThread && scriptedFirst != null) {
                Instant first = scriptedFirst;
                scriptedFirst = null;
                return first;
            }
            return now;
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
