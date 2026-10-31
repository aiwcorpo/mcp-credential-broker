package pl.aiwcorpo.mcp.broker.secret;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.support.MutableClock;
import tools.jackson.databind.json.JsonMapper;

/** Token lifecycle of the OpenBao client against a scripted fake: renew-self, re-login, fallback. */
class OpenBaoClientTest {

    private final List<String> calls = new CopyOnWriteArrayList<>();
    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-27T12:00:00Z"));
    private HttpServer server;
    private volatile int loginStatus = 200;
    private volatile int renewStatus = 200;
    private volatile long renewLease = 3600;
    private int issued;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/auth/approle/login", exchange -> {
            calls.add("login");
            issued++;
            respond(exchange, loginStatus, "{\"auth\":{\"client_token\":\"t" + issued + "\",\"lease_duration\":3600}}");
        });
        server.createContext("/v1/auth/token/renew-self", exchange -> {
            calls.add("renew:" + exchange.getRequestHeaders().getFirst("X-Vault-Token"));
            respond(exchange, renewStatus, "{\"auth\":{\"lease_duration\":" + renewLease + "}}");
        });
        server.createContext("/v1/secret/data/x", exchange -> {
            calls.add("read:" + exchange.getRequestHeaders().getFirst("X-Vault-Token"));
            respond(exchange, 200, "{\"data\":{\"data\":{}}}");
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void renewsTheTokenInsteadOfLoggingInAgain() {
        OpenBaoClient client = client();
        client.read("secret/data/x");
        clock.advance(Duration.ofMinutes(50));
        client.read("secret/data/x");
        assertThat(calls).containsExactly("login", "read:t1", "renew:t1", "read:t1");
    }

    @Test
    void logsInAgainNearMaxTtl() {
        OpenBaoClient client = client();
        client.read("secret/data/x");
        renewLease = 10;
        clock.advance(Duration.ofMinutes(50));
        client.read("secret/data/x");
        assertThat(calls).containsExactly("login", "read:t1", "renew:t1", "login", "read:t2");
    }

    @Test
    void keepsAValidTokenWhenRenewalAndLoginFail() {
        OpenBaoClient client = client();
        client.read("secret/data/x");
        renewStatus = 403;
        loginStatus = 400;
        clock.advance(Duration.ofMinutes(50));
        client.read("secret/data/x");
        assertThat(calls).containsExactly("login", "read:t1", "renew:t1", "login", "read:t1");

        clock.advance(Duration.ofMinutes(15));
        assertThatThrownBy(() -> client.read("secret/data/x")).isInstanceOf(SecretStoreUnavailableException.class);
    }

    @Test
    void aCallThatGotNoAnswerMakesTheNextOnesFailAtOnceForAWhile() throws InterruptedException {
        OpenBaoClient client = client(Duration.ofMillis(300));
        server.createContext("/v1/secret/data/slow", exchange -> {
            calls.add("slow");
            try {
                Thread.sleep(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.close();
        });
        assertThatThrownBy(() -> client.read("secret/data/slow")).isInstanceOf(SecretStoreUnavailableException.class);
        long start = System.nanoTime();
        assertThatThrownBy(() -> client.read("secret/data/x")).isInstanceOf(SecretStoreUnavailableException.class);
        assertThat(Duration.ofNanos(System.nanoTime() - start)).as("no network call").isLessThan(Duration.ofMillis(100));
        assertThat(calls).containsExactly("login", "slow");

        Thread.sleep(2200);
        client.read("secret/data/x");
        assertThat(calls).last().isEqualTo("read:t1");
    }

    private OpenBaoClient client() {
        return client(Duration.ofSeconds(2));
    }

    private OpenBaoClient client(Duration timeout) {
        BrokerProperties.OpenBao config = new BrokerProperties.OpenBao(
                URI.create("http://127.0.0.1:" + server.getAddress().getPort()), "role", "secret", "secret",
                "mcp/connections", "mcp/oauth-clients", "mcp/service-accounts", "transit", "mcp-credential-broker", timeout);
        return new OpenBaoClient(config, HttpClient.newHttpClient(), JsonMapper.builder().build(), clock);
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
