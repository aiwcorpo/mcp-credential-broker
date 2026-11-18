package pl.aiwcorpo.mcp.broker.system;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

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
import java.util.Arrays;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import tools.jackson.databind.json.JsonMapper;

/** The Jira and Confluence whoami against a real socket server: the body is capped and the whole exchange is bounded. */
class AtlassianDcAdapterTest {

    private ServerSocket server;
    private volatile Behavior behavior;

    private enum Behavior { OVERSIZED, HEADERS_THEN_SILENCE }

    @BeforeEach
    void startServer() throws IOException {
        server = new ServerSocket(0, 10, InetAddress.getLoopbackAddress());
        Thread acceptor = new Thread(() -> {
            while (!server.isClosed()) {
                try {
                    Socket socket = server.accept();
                    Thread handler = new Thread(() -> handle(socket), "whoami-test-handler");
                    handler.setDaemon(true);
                    handler.start();
                } catch (IOException e) {
                    return;
                }
            }
        }, "whoami-test-acceptor");
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
            if (behavior == Behavior.OVERSIZED) {
                byte[] body = new byte[UpstreamHttp.MAX_BODY_BYTES + 1];
                Arrays.fill(body, (byte) 'a');
                byte[] head = "{\"name\":\"".getBytes(StandardCharsets.US_ASCII);
                System.arraycopy(head, 0, body, 0, head.length);
                body[body.length - 2] = '"';
                body[body.length - 1] = '}';
                out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + body.length
                        + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                out.write(body);
                out.flush();
            } else {
                out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4000\r\n\r\n{"
                        .getBytes(StandardCharsets.US_ASCII));
                out.flush();
                while (in.read() >= 0) {
                    // Hold the connection open until the client gives up.
                }
            }
        } catch (IOException e) {
            // The client closing a connection it gave up on is the expected end.
        }
    }

    private AtlassianDcAdapter adapter() {
        URI base = URI.create("http://127.0.0.1:" + server.getLocalPort());
        HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        return new AtlassianDcAdapter(AtlassianDcAdapter.Product.JIRA, base, Duration.ofSeconds(1), client,
                JsonMapper.builder().build());
    }

    @Test
    void aBodyOverTheCapIsRefused() {
        behavior = Behavior.OVERSIZED;
        AtlassianDcAdapter adapter = adapter();
        assertThatThrownBy(() -> adapter.whoami(CredentialScheme.BEARER, SecretValue.of("dummy")))
                .isInstanceOf(UpstreamUnavailableException.class);
    }

    @Test
    void aBodyThatStallsAfterTheHeadersIsCutOffAtTheTimeout() {
        behavior = Behavior.HEADERS_THEN_SILENCE;
        AtlassianDcAdapter adapter = adapter();
        assertTimeoutPreemptively(Duration.ofSeconds(3), () -> assertThatThrownBy(
                () -> adapter.whoami(CredentialScheme.BEARER, SecretValue.of("dummy")))
                .isInstanceOf(UpstreamUnavailableException.class));
    }
}
