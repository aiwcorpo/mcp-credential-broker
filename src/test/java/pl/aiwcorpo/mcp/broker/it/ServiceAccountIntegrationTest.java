package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import tools.jackson.databind.JsonNode;

/**
 * The service-account type (CC-157) for Service Desk: the key is read from OpenBao
 * ({@code secret/data/mcp/service-accounts/servicedesk}), the user has no connection, nothing is written.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class ServiceAccountIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final String KEY_PATH = "secret/data/mcp/service-accounts/servicedesk";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @BeforeAll
    static void addServiceDesk() {
        env.putSystem(env.serviceDesk());
        env.awaitSystemSync();
    }

    @AfterAll
    static void removeServiceDesk() {
        env.removeSystem("servicedesk");
        env.awaitSystemSync();
    }

    @LocalServerPort
    int port;

    BrokerClient gateway;
    BrokerClient bff;
    TestTokens tokens = env.tokens;

    @BeforeEach
    void clients() {
        gateway = new BrokerClient(env.pki.clientContext(env.gatewayClient), port);
        bff = new BrokerClient(env.pki.clientContext(env.bffClient), port);
    }

    @Test
    void handsOutTheKeyOfTheAccountWithoutAnyConnectionOfTheUser(CapturedOutput output) {
        String key = "sd-key-" + UUID.randomUUID();
        writeKey("{\"value\":\"" + key + "\"}");
        String sub = UUID.randomUUID().toString();

        String rid = TestTokens.newRequestId();
        BrokerClient.Response resolved = resolve(sub, rid);

        assertThat(resolved.status()).isEqualTo(200);
        JsonNode body = resolved.json();
        assertThat(Contracts.brokerSchemaErrors("ResolvedCredential", body)).isEmpty();
        assertThat(body.path("scheme").stringValue()).isEqualTo("Bearer");
        assertThat(body.path("value").stringValue()).isEqualTo(key);
        assertThat(body.path("type").stringValue()).isEqualTo("service-account");
        assertThat(body.path("expiresAt").isNull()).isTrue();
        assertThat(body.path("cacheTtlSeconds").asInt()).isEqualTo(60);
        assertThat(resolved.header("Cache-Control")).isEqualTo("no-store");

        BrokerClient.Response connections = bff.send("GET", "/v1/connections", tokens.bffUser(sub, "alice"), null, null);
        assertThat(connections.json()).as("GET /v1/connections does not list the account").isEmpty();
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(e -> {
            assertThat(e.path("outcome").stringValue()).isEqualTo("ok");
            assertThat(e.path("server").stringValue()).isEqualTo("mcp-servicedesk");
            assertThat(e.path("credentialType").stringValue()).isEqualTo("service-account");
        });
        assertThat(output.getAll()).doesNotContain(key);
    }

    @Test
    void theExpiryFollowsTheRotationAndBoundsTheCache() {
        Instant rotation = Instant.now().plusSeconds(25);
        writeKey("{\"value\":\"rotating-key\",\"expires_at\":\"" + rotation.toString() + "\"}");
        BrokerClient.Response resolved = resolve(UUID.randomUUID().toString(), TestTokens.newRequestId());
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(Instant.parse(resolved.json().path("expiresAt").stringValue())).isBeforeOrEqualTo(rotation);
        assertThat(resolved.json().path("cacheTtlSeconds").asInt()).isBetween(1, 25);
    }

    @Test
    void aRotationInOpenBaoIsPickedUpAtOnce() {
        writeKey("{\"value\":\"first-key\"}");
        assertThat(resolve(UUID.randomUUID().toString(), TestTokens.newRequestId()).json().path("value").stringValue())
                .isEqualTo("first-key");
        writeKey("{\"value\":\"second-key\"}");
        assertThat(resolve(UUID.randomUUID().toString(), TestTokens.newRequestId()).json().path("value").stringValue())
                .isEqualTo("second-key");
    }

    @Test
    void aMissingExpiredOrBrokenKeyFailsClosed(CapturedOutput output) {
        for (String entry : new String[] {"{\"expires_at\":\"2020-01-01T00:00:00Z\",\"value\":\"old-key\"}", "{\"note\":\"empty\"}",
                "{\"value\":\"two words\"}", "{\"value\":\"k\",\"expires_at\":\"tomorrow\"}"}) {
            writeKey(entry);
            String rid = TestTokens.newRequestId();
            BrokerClient.Response resolved = resolve(UUID.randomUUID().toString(), rid);
            assertThat(resolved.status()).as(entry).isEqualTo(503);
            assertThat(resolved.body()).isEqualTo("{\"error\":\"upstream_unavailable\"}");
            assertThat(AuditLines.of(output, rid)).singleElement()
                    .satisfies(e -> assertThat(e.path("outcome").stringValue()).isEqualTo("error"));
        }
        env.bao("DELETE", "secret/metadata/mcp/service-accounts/servicedesk", null);
        assertThat(resolve(UUID.randomUUID().toString(), TestTokens.newRequestId()).status()).isEqualTo(503);
        assertThat(output.getAll()).doesNotContain("old-key");
    }

    @Test
    void usersCannotConnectToAServiceAccountSystem() {
        String sub = UUID.randomUUID().toString();
        assertThat(bff.send("PUT", "/v1/connections/servicedesk/secret", tokens.bffUser(sub, "alice"), null,
                "{\"secret\":\"alice-pat\"}").status()).isEqualTo(400);
        assertThat(bff.send("POST", "/v1/connections/servicedesk/oauth/start", tokens.bffUser(sub, "alice"), null,
                "{\"returnPath\":\"/catalog\"}").status()).isEqualTo(400);
        assertThat(bff.send("DELETE", "/v1/connections/servicedesk", tokens.bffUser(sub, "alice"), null, null).status())
                .isEqualTo(204);
    }

    @Test
    void theCatalogListsTheSystemWithItsType() {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response systems = gateway.send("GET", "/v1/systems", tokens.gatewayService(rid), rid, null);
        JsonNode info = null;
        for (JsonNode candidate : systems.json()) {
            if ("servicedesk".equals(candidate.path("system").stringValue())) {
                info = candidate;
            }
        }
        assertThat(info).isNotNull();
        assertThat(Contracts.brokerSchemaErrors("SystemInfo", info)).isEmpty();
        assertThat(info.path("defaultType").stringValue()).isEqualTo("service-account");
    }

    private BrokerClient.Response resolve(String sub, String rid) {
        return gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", rid, "get_ticket"), rid,
                "{\"system\":\"servicedesk\"}");
    }

    private static void writeKey(String data) {
        assertThat(env.bao("POST", KEY_PATH, "{\"data\":" + data + "}").statusCode()).isEqualTo(200);
    }
}
