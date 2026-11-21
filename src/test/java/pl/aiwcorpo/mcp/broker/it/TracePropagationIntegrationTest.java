package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;

/** The broker continues the trace of the gateway's call and exports spans that name no secret, token or user. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TracePropagationIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final String TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";
    private static final String PARENT_SPAN_ID = "00f067aa0ba902b7";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @LocalServerPort
    int port;

    BrokerClient gateway;
    BrokerClient bff;

    @BeforeEach
    void clients() {
        gateway = new BrokerClient(env.pki.clientContext(env.gatewayClient), port);
        bff = new BrokerClient(env.pki.clientContext(env.bffClient), port);
    }

    @Test
    void aResolveWithATraceparentIsExportedAsAChildOfThatSpanAndHoldsNoSecret() {
        String sub = UUID.randomUUID().toString();
        assertThat(bff.send("PUT", "/v1/connections/jira/secret", env.tokens.bffUser(sub, "alice"), null,
                "{\"secret\":\"alice-pat\"}").status()).isEqualTo(200);
        String rid = TestTokens.newRequestId();
        String gatewayToken = env.tokens.gatewayUser(sub, "alice", rid);
        BrokerClient.Response resolved = gateway.send("POST", "/v1/credentials/resolve", gatewayToken, rid,
                "{\"system\":\"jira\"}", Map.of("traceparent", "00-" + TRACE_ID + "-" + PARENT_SPAN_ID + "-01"));
        assertThat(resolved.status()).isEqualTo(200);

        byte[] traceId = HexFormat.of().parseHex(TRACE_ID);
        byte[] parentSpanId = HexFormat.of().parseHex(PARENT_SPAN_ID);
        await().atMost(Duration.ofSeconds(15)).untilAsserted(() -> {
            assertThat(contains(exported(), traceId)).as("exported spans of the trace").isTrue();
            assertThat(contains(exported(), parentSpanId)).as("the client's span is the parent").isTrue();
        });
        String text = new String(exported(), StandardCharsets.ISO_8859_1);
        assertThat(text).doesNotContain("alice-pat").doesNotContain(gatewayToken).doesNotContain(sub).doesNotContain("alice")
                .doesNotContain("Bearer").doesNotContain("/v1/connections/jira/secret");
    }

    private static byte[] exported() {
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        env.collector.bodies().forEach(all::writeBytes);
        return all.toByteArray();
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}
