package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;

/** Health probes keep their metric but never leave the process as a span; any other path, however close, is traced as before. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HealthProbeTracingIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @LocalServerPort
    int port;

    @Autowired
    MeterRegistry meters;

    private int counter;

    private String get(String path, SSLContext tls, String traceId) throws Exception {
        HttpResponse<String> response = HttpClient.newBuilder().sslContext(tls).build().send(
                HttpRequest.newBuilder(URI.create("https://localhost:" + port + path))
                        .header("traceparent", "00-" + traceId + "-b7ad6b7169203331-01").GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return response.statusCode() + " " + response.body();
    }

    private String newTraceId() {
        return String.format("%032x", 0x5a0000000000L + (++counter) + System.nanoTime() % 1_000_000 * 1_000_000_000L);
    }

    private boolean exported(String traceId) {
        StringBuilder all = new StringBuilder();
        env.collector.bodies().forEach(body -> all.append(new String(body, StandardCharsets.ISO_8859_1)));
        byte[] raw = java.util.HexFormat.of().parseHex(traceId);
        return all.toString().contains(new String(raw, StandardCharsets.ISO_8859_1));
    }

    private void assertExported(String path, SSLContext tls, boolean expected) throws Exception {
        String traceId = newTraceId();
        get(path, tls, traceId);
        // A request that is traced and follows the probe travels in the same batches: once it is out, a withheld probe span would be too.
        String marker = newTraceId();
        get("/actuator/info", env.pki.clientContext(env.gatewayClient), marker);
        await().atMost(Duration.ofSeconds(15)).until(() -> exported(marker));
        assertThat(exported(traceId)).as(path).isEqualTo(expected);
    }

    private long healthRequests() {
        return meters.find("http.server.requests").tag("uri", "/actuator/health").timers().stream().mapToLong(Timer::count).sum();
    }

    @Test
    void aHealthProbeIsNotExportedButIsCounted() throws Exception {
        SSLContext caller = env.pki.clientContext(env.gatewayClient);
        long before = healthRequests();
        assertExported("/actuator/health", caller, false);
        assertExported("/actuator/health/liveness", caller, false);
        assertThat(healthRequests()).isGreaterThan(before);
    }

    @Test
    void aPathThatOnlyNormalisesToTheHealthPathIsStillExported() throws Exception {
        SSLContext caller = env.pki.clientContext(env.gatewayClient);
        for (String path : List.of("//actuator/health", "/actuator//health", "/x/../actuator/health", "/x/..;/actuator/health",
                "/actuator/./health", "/actuator/health;a=b", "/actuator/%68ealth", "/actuator/%2e/health", "/v1/../actuator/health")) {
            assertExported(path, caller, true);
        }
    }

    @Test
    void pathsThatOnlyLookLikeHealthAreStillExported() throws Exception {
        SSLContext caller = env.pki.clientContext(env.gatewayClient);
        for (String path : List.of("/actuator/healthx", "/actuator/info", "/mcp", "/s/x/mcp/actuator/health", "/actuator/health-check",
                "/v1/actuator/health")) {
            assertExported(path, caller, true);
        }
    }
}
