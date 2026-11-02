package pl.aiwcorpo.mcp.broker.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.MutableClock;
import pl.aiwcorpo.mcp.broker.support.TestTokens;

/**
 * The JWKS fetch against a real socket server. Plain HTTP only: the test tree has no TLS material, and the
 * bound is a timeout on the whole exchange, independent of the transport.
 */
class JwksFetchTest {

    private static final String KID = "test-gw-2026-10-a";

    private ServerSocket server;
    private final AtomicInteger connections = new AtomicInteger();
    private volatile Behavior behavior = Behavior.GOOD;

    private enum Behavior { GOOD, HEADERS_THEN_SILENCE, OVERSIZED }

    @BeforeEach
    void startServer() throws IOException {
        server = new ServerSocket(0, 10, InetAddress.getLoopbackAddress());
        Thread acceptor = new Thread(() -> {
            while (!server.isClosed()) {
                try {
                    Socket socket = server.accept();
                    connections.incrementAndGet();
                    Thread handler = new Thread(() -> handle(socket), "jwks-test-handler");
                    handler.setDaemon(true);
                    handler.start();
                } catch (IOException e) {
                    return;
                }
            }
        }, "jwks-test-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    @AfterEach
    void stopServer() throws IOException {
        server.close();
    }

    private void handle(Socket socket) {
        try (socket) {
            InputStream in = socket.getInputStream();
            int matched = 0;
            while (matched < 4) {
                int b = in.read();
                if (b < 0) {
                    return;
                }
                matched = (b == '\r' || b == '\n') ? matched + 1 : 0;
            }
            OutputStream out = socket.getOutputStream();
            switch (behavior) {
                case HEADERS_THEN_SILENCE -> {
                    out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4000\r\n\r\n{"
                            .getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                    while (in.read() >= 0) {
                        // Hold the connection open until the client gives up.
                    }
                }
                case OVERSIZED -> {
                    byte[] body = new byte[JwksGatewayKeys.MAX_BODY_BYTES + 1024];
                    java.util.Arrays.fill(body, (byte) ' ');
                    out.write(("HTTP/1.1 200 OK\r\nContent-Length: " + body.length + "\r\nConnection: close\r\n\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
                    out.write(body);
                    out.flush();
                }
                default -> {
                    byte[] body = Contracts.text(TestTokens.GATEWAY_JWKS_PATH).getBytes(StandardCharsets.UTF_8);
                    out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + body.length
                            + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    out.write(body);
                    out.flush();
                }
            }
        } catch (IOException e) {
            // The client closing a connection it gave up on is the expected end.
        }
    }

    private JwksGatewayKeys keys(MutableClock clock, Duration timeout) {
        URI uri = URI.create("http://127.0.0.1:" + server.getLocalPort() + "/jwks");
        return JwksGatewayKeys.fromUri(uri, HttpClient.newHttpClient(), timeout, clock, Duration.ofMinutes(5),
                Duration.ofSeconds(10), Duration.ofHours(1));
    }

    @Test
    @Timeout(20)
    void fetchThatStallsAfterTheHeadersIsCutOffAndDoesNotKeepTheLock() {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-27T12:00:00Z"));
        JwksGatewayKeys keys = keys(clock, Duration.ofSeconds(1));
        behavior = Behavior.HEADERS_THEN_SILENCE;

        long started = System.nanoTime();
        assertThatThrownBy(() -> keys.find(KID)).isInstanceOf(KeySourceUnavailableException.class);
        Duration took = Duration.ofNanos(System.nanoTime() - started);
        assertThat(took).as("bounded by the fetch timeout, not by the silent server").isLessThan(Duration.ofSeconds(5));

        behavior = Behavior.GOOD;
        clock.advance(Duration.ofSeconds(11));
        assertThat(keys.find(KID)).as("the lock was released, the next attempt works").isPresent();
        assertThat(connections.get()).isEqualTo(2);
    }

    @Test
    void oversizedResponseIsRejected() {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-27T12:00:00Z"));
        JwksGatewayKeys keys = keys(clock, Duration.ofSeconds(2));
        behavior = Behavior.OVERSIZED;
        assertThatThrownBy(() -> keys.find(KID)).isInstanceOf(KeySourceUnavailableException.class);
    }

    @Test
    void lockWaitOutlastsOneFetchButNotTwo() {
        MutableClock clock = new MutableClock(Instant.now());
        JwksGatewayKeys keys = keys(clock, Duration.ofSeconds(5));
        assertThat(keys.lockWait()).isEqualTo(Duration.ofSeconds(6));
        assertThat(JwksGatewayKeys.lockWaitFor(Duration.ofMillis(1500))).isEqualTo(Duration.ofMillis(2500));
    }
}
