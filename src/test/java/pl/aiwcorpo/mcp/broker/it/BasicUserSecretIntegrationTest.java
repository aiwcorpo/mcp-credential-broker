package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
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

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import pl.aiwcorpo.mcp.broker.system.SystemDefinition;
import tools.jackson.databind.JsonNode;

/** A system whose user secret is a login plus a token (CC-222), here a Confluence host configured as a cloud installation. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class BasicUserSecretIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final String TOKEN = "basic-api-token-0001";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @BeforeAll
    static void addCloudWiki() {
        env.putSystem(new SystemDefinition("cloudwiki", URI.create(env.confluenceUrl()), "atlassian-dc", "confluence",
                List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, CredentialScheme.BASIC, null, null, null, null,
                null, BrokerProperties.Deployment.CLOUD, SystemDefinition.newToken(), SystemDefinition.newToken()));
        env.awaitSystemSync();
    }

    @AfterAll
    static void removeCloudWiki() {
        env.removeSystem("cloudwiki");
        env.awaitSystemSync();
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
    void theCatalogTellsTheLoginFieldAndTheInstallation() {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response systems = gateway.send("GET", "/v1/systems", env.tokens.gatewayService(rid), rid, null);
        assertThat(systems.status()).isEqualTo(200);
        for (JsonNode system : systems.json()) {
            assertThat(Contracts.brokerSchemaErrors("SystemInfo", system)).isEmpty();
        }
        JsonNode cloudwiki = systems.json().get(0);
        assertThat(cloudwiki.path("system").stringValue()).isEqualTo("cloudwiki");
        assertThat(cloudwiki.path("userSecretScheme").stringValue()).isEqualTo("Basic");
        assertThat(cloudwiki.path("deployment").stringValue()).isEqualTo("cloud");
        JsonNode jira = systems.json().get(3);
        assertThat(jira.path("userSecretScheme").stringValue()).isEqualTo("Bearer");
        assertThat(jira.has("deployment")).as("not configured, not told").isFalse();
        JsonNode opensearch = systems.json().get(4);
        assertThat(opensearch.has("userSecretScheme")).as("no user-secret, no scheme").isFalse();
    }

    @Test
    void aLoginAndATokenAreStoredAsOnePairAndResolvedAsBasic(CapturedOutput output) {
        String sub = UUID.randomUUID().toString();
        String rid = TestTokens.newRequestId();
        BrokerClient.Response put = bff.send("PUT", "/v1/connections/cloudwiki/secret", env.tokens.bffUser(sub, "alice"), rid,
                "{\"username\":\"alice.smith\",\"secret\":\"" + TOKEN + "\"}");

        assertThat(put.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("PutSecretResponse", put.json())).isEmpty();
        assertThat(put.json().path("backendUser").stringValue()).isEqualTo("alice.smith");
        assertThat(put.body()).doesNotContain(TOKEN);

        String resolveRid = TestTokens.newRequestId();
        BrokerClient.Response resolved = gateway.send("POST", "/v1/credentials/resolve",
                env.tokens.gatewayUser(sub, "alice", resolveRid), resolveRid, "{\"system\":\"cloudwiki\"}");
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("ResolvedCredential", resolved.json())).isEmpty();
        assertThat(resolved.json().path("scheme").stringValue()).isEqualTo("Basic");
        assertThat(resolved.json().path("type").stringValue()).isEqualTo("user-secret");
        assertThat(new String(Base64.getDecoder().decode(resolved.json().path("value").stringValue()), StandardCharsets.UTF_8))
                .isEqualTo("alice.smith:" + TOKEN);
        assertThat(output.getAll()).doesNotContain(TOKEN).doesNotContain(Base64.getEncoder()
                .encodeToString(("alice.smith:" + TOKEN).getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void theUsernameNeverAppearsInLogsOrAnswers(CapturedOutput output) {
        String sub = UUID.randomUUID().toString();
        BrokerClient.Response put = bff.send("PUT", "/v1/connections/cloudwiki/secret", env.tokens.bffUser(sub, "alice"), null,
                "{\"username\":\"login-only-in-the-body\",\"secret\":\"invalid-" + TOKEN + "\"}");
        assertThat(put.status()).isEqualTo(422);
        assertThat(put.body()).doesNotContain("login-only-in-the-body");
        assertThat(output.getAll()).doesNotContain("login-only-in-the-body");
    }

    @Test
    void aBasicSystemWithoutAUsernameAndASingleTokenSystemWithOneAreRefused() {
        String sub = UUID.randomUUID().toString();
        assertThat(bff.send("PUT", "/v1/connections/cloudwiki/secret", env.tokens.bffUser(sub, "alice"), null,
                "{\"secret\":\"" + TOKEN + "\"}").status()).isEqualTo(400);
        assertThat(bff.send("PUT", "/v1/connections/jira/secret", env.tokens.bffUser(sub, "alice"), null,
                "{\"username\":\"alice\",\"secret\":\"alice-pat\"}").status()).isEqualTo(400);
    }

    @Test
    void aUsernameThatBreaksTheContractPatternIsRefusedAndNotEchoed(CapturedOutput output) {
        String sub = UUID.randomUUID().toString();
        for (String bad : new String[] {"a:b", "a\\u200bb", "a\\u0007b", "a\\u2028b", "a\\u202eb"}) {
            BrokerClient.Response put = bff.send("PUT", "/v1/connections/cloudwiki/secret", env.tokens.bffUser(sub, "alice"), null,
                    "{\"username\":\"" + bad + "\",\"secret\":\"" + TOKEN + "\"}");
            assertThat(put.status()).as(bad).isEqualTo(400);
            assertThat(put.body()).isEqualTo("{\"error\":\"invalid_request\"}");
        }
        assertThat(output.getAll()).doesNotContain("a:b");
    }
}
