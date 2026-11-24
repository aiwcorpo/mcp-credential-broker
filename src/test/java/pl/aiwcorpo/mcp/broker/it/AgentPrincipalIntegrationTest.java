package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import pl.aiwcorpo.mcp.broker.system.SystemDefinition;

/** Tokens with pty and resource (CC-260, CC-261) over real mTLS: who may resolve what, and which calls refuse an agent. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class AgentPrincipalIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final String OPEN_DESK = "opendesk";
    private static final String CLOSED_DESK = "closeddesk";
    private static final String FLAGGED_DESK = "flaggeddesk";
    private static final String RESOURCE = "opendesk://ticket/SD-1042";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @BeforeAll
    static void addSystems() {
        env.putSystem(desk(OPEN_DESK).withAgentsAllowed(true));
        env.putSystem(desk(CLOSED_DESK));
        // A row an older instance left behind: the flag set, service-account gone.
        env.putSystem(new SystemDefinition(FLAGGED_DESK, URI.create(env.upstreamUrl()), "generic-rest", null,
                List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, CredentialScheme.BEARER, null, null, null, null, null,
                null, SystemDefinition.newToken(), SystemDefinition.newToken()).withAgentsAllowed(true));
        for (String id : List.of(OPEN_DESK, CLOSED_DESK)) {
            assertThat(env.bao("POST", "secret/data/mcp/service-accounts/" + id, "{\"data\":{\"value\":\"" + keyOf(id) + "\"}}")
                    .statusCode()).isEqualTo(200);
        }
        env.awaitSystemSync();
    }

    @AfterAll
    static void removeSystems() {
        env.removeSystem(FLAGGED_DESK);
        for (String id : List.of(OPEN_DESK, CLOSED_DESK)) {
            env.removeSystem(id);
            env.bao("DELETE", "secret/metadata/mcp/service-accounts/" + id, null);
        }
        env.awaitSystemSync();
    }

    @LocalServerPort
    int port;

    BrokerClient gateway;
    final TestTokens tokens = env.tokens;

    @BeforeEach
    void clients() {
        gateway = new BrokerClient(env.pki.clientContext(env.gatewayClient), port);
    }

    private static SystemDefinition desk(String id) {
        return new SystemDefinition(id, URI.create(env.upstreamUrl()), "generic-rest", null, List.of(CredentialType.SERVICE_ACCOUNT),
                CredentialType.SERVICE_ACCOUNT, CredentialScheme.BEARER, null, null, null, null, null, null, SystemDefinition.newToken(),
                SystemDefinition.newToken());
    }

    private static String keyOf(String id) {
        return "key-of-" + id + "-for-test";
    }

    private static Map<String, Object> claims(Object... pairs) {
        Map<String, Object> map = new HashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put((String) pairs[i], pairs[i + 1]);
        }
        return map;
    }

    private BrokerClient.Response call(String method, String path, String body, Map<String, Object> claims, String rid) {
        return gateway.send(method, path, tokens.gatewayUserWithClaims(UUID.randomUUID().toString(), "service-account-agent-triage", rid, claims),
                rid, body);
    }

    private BrokerClient.Response resolve(String system, Map<String, Object> claims, String rid) {
        return call("POST", "/v1/credentials/resolve", "{\"system\":\"" + system + "\"}", claims, rid);
    }

    @Test
    void anAgentGetsTheSharedKeyOnlyOfASystemThatAllowsAgents(CapturedOutput output) {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response allowed = resolve(OPEN_DESK, claims("pty", "agent", "tool", "get_ticket"), rid);
        assertThat(allowed.status()).isEqualTo(200);
        assertThat(allowed.json().path("value").stringValue()).isEqualTo(keyOf(OPEN_DESK));
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> {
            assertThat(event.path("outcome").stringValue()).isEqualTo("ok");
            assertThat(event.path("principalType").stringValue()).isEqualTo("agent");
        });

        String refusedRid = TestTokens.newRequestId();
        BrokerClient.Response refused = resolve(CLOSED_DESK, claims("pty", "agent", "tool", "get_ticket"), refusedRid);
        assertThat(refused.status()).isEqualTo(403);
        assertThat(refused.body()).isEqualTo("{\"error\":\"principal_not_eligible\"}");
        assertThat(AuditLines.of(output, refusedRid)).singleElement().satisfies(event -> {
            assertThat(event.path("outcome").stringValue()).isEqualTo("denied");
            assertThat(event.path("reason").stringValue()).isEqualTo("principal_not_eligible");
            assertThat(event.path("principalType").stringValue()).isEqualTo("agent");
        });
        assertThat(output.getAll()).doesNotContain(keyOf(CLOSED_DESK));
    }

    @Test
    void anAgentIsRefusedAUserSecretSystemWithoutAnyConnectionLookup(CapturedOutput output) {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response refused = resolve("jira", claims("pty", "agent", "tool", "get_issue"), rid);

        assertThat(refused.status()).isEqualTo(403);
        assertThat(refused.body()).isEqualTo("{\"error\":\"principal_not_eligible\"}");
        assertThat(AuditLines.of(output, rid)).singleElement()
                .satisfies(event -> assertThat(event.path("reason").stringValue()).isEqualTo("principal_not_eligible"));
    }

    @Test
    void aStoredRowWithAgentsAllowedButNoServiceAccountStaysServedToHumansAndRefusedToAgents() {
        BrokerClient.Response human = resolve(FLAGGED_DESK, claims("tool", "get_ticket"), TestTokens.newRequestId());
        assertThat(human.status()).as("served: the user has no connection, which is 409, not 422 system_not_configured").isEqualTo(409);

        BrokerClient.Response agent = resolve(FLAGGED_DESK, claims("pty", "agent", "tool", "get_ticket"), TestTokens.newRequestId());
        assertThat(agent.status()).isEqualTo(403);
        assertThat(agent.body()).isEqualTo("{\"error\":\"principal_not_eligible\"}");
    }

    @Test
    void aHumanStillGetsTheSharedKeyOfASystemThatDoesNotAllowAgents() {
        BrokerClient.Response resolved = resolve(CLOSED_DESK, claims("tool", "get_ticket"), TestTokens.newRequestId());
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(resolved.json().path("value").stringValue()).isEqualTo(keyOf(CLOSED_DESK));
    }

    @Test
    void aResolveForAResourceCarriesTheResourceInsteadOfTheTool() {
        assertThat(resolve(CLOSED_DESK, claims("tool", null, "resource", RESOURCE), TestTokens.newRequestId()).status()).isEqualTo(200);
        assertThat(resolve(OPEN_DESK, claims("tool", null, "resource", RESOURCE, "pty", "agent"), TestTokens.newRequestId()).status())
                .isEqualTo(200);
    }

    @Test
    void aTokenWithToolAndResourceOrNeitherIsUnauthorized() {
        assertThat(resolve(CLOSED_DESK, claims("tool", "get_ticket", "resource", RESOURCE), TestTokens.newRequestId()).status())
                .isEqualTo(401);
        assertThat(resolve(CLOSED_DESK, claims("tool", null), TestTokens.newRequestId()).status()).isEqualTo(401);
    }

    @Test
    void aMalformedPrincipalClaimIsUnauthorizedBeforeAnythingIsResolved() {
        Map<String, Object> actor = claims("sub", "agent-sub", "azp", "agent-triage");
        List<Map<String, Object>> refused = List.of(
                claims("tool", "get_ticket", "pty", "user"),
                claims("tool", "get_ticket", "pty", "robot"),
                claims("tool", "get_ticket", "pty", "delegated"),
                claims("tool", "get_ticket", "pty", "agent", "act", actor),
                claims("tool", "get_ticket", "act", actor),
                claims("tool", "get_ticket", "pty", "delegated", "act", claims("sub", "agent-sub")));
        for (Map<String, Object> token : refused) {
            assertThat(resolve(OPEN_DESK, token, TestTokens.newRequestId()).status()).as(token.toString()).isEqualTo(401);
        }
    }

    @Test
    void theAuthenticatorCallsRefuseAnAgentBeforeAnyBodyIsRead(CapturedOutput output) {
        Map<String, Object> agent = claims("pty", "agent", "tool", "update_issue");
        String statusRid = TestTokens.newRequestId();
        assertThat(call("GET", "/v1/authenticator", null, agent, statusRid).status()).isEqualTo(403);
        String verifyRid = TestTokens.newRequestId();
        BrokerClient.Response verify = call("POST", "/v1/authenticator/verify", "not even json", agent, verifyRid);
        assertThat(verify.status()).isEqualTo(403);
        assertThat(verify.body()).isEqualTo("{\"error\":\"principal_not_eligible\"}");
        String invalidateRid = TestTokens.newRequestId();
        assertThat(call("POST", "/v1/authenticator/invalidate-codes", null, agent, invalidateRid).status()).isEqualTo(403);

        for (String rid : List.of(verifyRid, invalidateRid)) {
            assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> {
                assertThat(event.path("event").stringValue()).isEqualTo("authenticator");
                assertThat(event.path("reason").stringValue()).isEqualTo("principal_not_eligible");
                assertThat(event.path("principalType").stringValue()).isEqualTo("agent");
            });
        }
    }

    @Test
    void aDelegatedCallReadsTheAuthenticatorOfTheHuman() {
        Map<String, Object> delegated = claims("pty", "delegated", "tool", "update_issue",
                "act", claims("sub", "agent-sub", "azp", "agent-triage"));
        assertThat(call("GET", "/v1/authenticator", null, delegated, TestTokens.newRequestId()).status()).isEqualTo(200);
    }

    @Test
    void aTokenWithPtyIsRefusedWhereTheContractDoesNotServeIt() {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response systems = call("GET", "/v1/systems", null, claims("pty", "agent", "tool", null), rid);
        assertThat(systems.status()).isEqualTo(403);
        assertThat(systems.body()).isEqualTo("{\"error\":\"forbidden\"}");
        assertThat(call("GET", "/v1/systems", null, claims("tool", null), TestTokens.newRequestId()).status()).isEqualTo(200);
    }
}
