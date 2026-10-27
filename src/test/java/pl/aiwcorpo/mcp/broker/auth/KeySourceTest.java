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
