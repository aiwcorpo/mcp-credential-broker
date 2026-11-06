package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.BrokerProcess;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.InvalidationListener;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import tools.jackson.databind.JsonNode;

/** C4 {@code /v1/admin/systems}: the portal BFF with the token of an administrator, over real mTLS against PostgreSQL, Redis and OpenBao. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class SystemAdminIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final Set<String> STANDARD = Set.of("jira", "confluence", "gitlab", "opensearch");
    private static final String SECRET = "test-only-system-client-secret-0001";
    private static final int PORT_SECOND_INSTANCE = 18718;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @LocalServerPort
    int port;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    SystemRegistry registry;

    BrokerClient bff;
    BrokerClient gateway;
    final TestTokens tokens = env.tokens;
    final String adminSub = UUID.randomUUID().toString();

    @BeforeEach
    void clients() {
        bff = new BrokerClient(env.pki.clientContext(env.bffClient), port);
        gateway = new BrokerClient(env.pki.clientContext(env.gatewayClient), port);
    }

    @AfterEach
    void removeWhatTheTestCreated() {
        for (var system : env.systems.findAll()) {
            if (!STANDARD.contains(system.id())) {
                env.bao("DELETE", "secret/metadata/mcp/oauth-clients/" + system.id(), null);
                jdbc.sql("delete from connection where system = :system").param("system", system.id()).update();
                env.removeSystem(system.id());
            }
        }
        registry.reload();
    }

    @AfterAll
    static void letOtherBrokersSeeTheCleanup() {
        env.awaitSystemSync();
    }

    private static String newId() {
        return "n" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
    }

    private static String gitlabBody(String baseUrl, String authorizeUrl, String tokenUrl, String clientId, String secret,
            String scopes) {
        return "{\"baseUrl\":\"" + baseUrl + "\",\"adapter\":\"gitlab\",\"supportedTypes\":[\"user-oauth\",\"user-secret\"],"
                + "\"defaultType\":\"user-oauth\",\"secretScheme\":\"Bearer\",\"oauth\":{\"clientId\":\"" + clientId + "\","
                + (secret == null ? "" : "\"clientSecret\":\"" + secret + "\",") + "\"authorizeUrl\":\"" + authorizeUrl
                + "\",\"tokenUrl\":\"" + tokenUrl + "\",\"scopes\":" + scopes + "}}";
    }

    private String gitlabBody(String secret) {
        return gitlabBody(env.gitlab.url(), "https://gitlab.test/oauth/authorize", "https://gitlab.test/oauth/token", "client-one",
                secret, "[\"read_api\"]");
    }

    private BrokerClient.Response put(String id, String body, Map<String, String> headers) {
        return bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), TestTokens.newRequestId(), body, headers);
    }

    private BrokerClient.Response create(String id, String body) {
        return put(id, body, Map.of("If-None-Match", "*"));
    }

    private BrokerClient.Response get(String id) {
        return bff.send("GET", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), TestTokens.newRequestId(), null);
    }

    private BrokerClient.Response delete(String id) {
        return bff.send("DELETE", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), TestTokens.newRequestId(), null);
    }

    private BrokerClient.Response list() {
        return bff.send("GET", "/v1/admin/systems", tokens.bffAdmin(adminSub, "root"), TestTokens.newRequestId(), null);
    }

    private JsonNode storedSecret(String id) {
        var response = env.bao("GET", "secret/data/mcp/oauth-clients/" + id, null);
        return response.statusCode() == 200 ? Contracts.JSON.readTree(response.body()).path("data").path("data") : null;
    }

    @Test
    void aSystemIsCreatedReadReplacedAndDeletedOverHttp() {
        String id = newId();
        BrokerClient.Response created = create(id, gitlabBody(SECRET));
        assertThat(created.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("SystemAdminView", created.json())).isEmpty();
        assertThat(created.json().path("system").stringValue()).isEqualTo(id);
        assertThat(created.json().path("oauth").path("clientSecretSet").booleanValue()).isTrue();
        String etag = created.header("ETag");
        assertThat(etag).matches("^\"[A-Za-z0-9_-]{8,128}\"$");

        BrokerClient.Response read = get(id);
        assertThat(read.status()).isEqualTo(200);
        assertThat(read.header("ETag")).isEqualTo(etag);
        assertThat(read.json()).isEqualTo(created.json());

        JsonNode listed = list().json();
        assertThat(listed.valueStream().map(system -> system.path("system").stringValue()).toList())
                .contains(id, "jira", "gitlab").isSorted();
        for (JsonNode system : listed) {
            assertThat(Contracts.brokerSchemaErrors("SystemAdminView", system)).isEmpty();
        }

        String rid = TestTokens.newRequestId();
        BrokerClient.Response readers = gateway.send("GET", "/v1/systems", tokens.gatewayService(rid), rid, null);
        assertThat(readers.json().valueStream().filter(system -> id.equals(system.path("system").stringValue())).findFirst())
                .hasValueSatisfying(system -> {
                    assertThat(Contracts.brokerSchemaErrors("SystemInfo", system)).isEmpty();
                    assertThat(system.path("supportedTypes").valueStream().map(JsonNode::stringValue).toList())
                            .containsExactly("user-oauth", "user-secret");
                    assertThat(system.path("oauthScopes").valueStream().map(JsonNode::stringValue).toList()).containsExactly("read_api");
                });

        String changed = gitlabBody(env.gitlab.url(), "https://gitlab.test/oauth/authorize", "https://gitlab.test/oauth/token",
                "client-one", null, "[\"read_api\",\"api\"]");
        BrokerClient.Response replaced = put(id, changed, Map.of("If-Match", etag));
        assertThat(replaced.status()).isEqualTo(200);
        assertThat(replaced.header("ETag")).isNotEqualTo(etag);
        assertThat(replaced.json().path("oauth").path("scopes").size()).isEqualTo(2);
        assertThat(replaced.json().path("oauth").path("clientSecretSet").booleanValue()).as("kept").isTrue();

        assertThat(delete(id).status()).isEqualTo(204);
        assertThat(get(id).status()).isEqualTo(404);
        assertThat(delete(id).status()).as("idempotent").isEqualTo(204);
        assertThat(registry.find(id)).isEmpty();
        assertThat(storedSecret(id)).as("the client secret went with the system").isNull();
    }

    @Test
    void preconditionsAreEnforced() {
        String id = newId();
        assertThat(put(id, gitlabBody(SECRET), Map.of()).status()).as("neither header").isEqualTo(428);
        assertThat(put(id, gitlabBody(SECRET), Map.of("If-Match", "\"Zx8Tq2LmWk93vNpA\"")).status())
                .as("replace of a system that is not there").isEqualTo(412);
        BrokerClient.Response created = create(id, gitlabBody(SECRET));
        assertThat(created.status()).isEqualTo(200);
        String etag = created.header("ETag");

        BrokerClient.Response again = create(id, gitlabBody(SECRET));
        assertThat(again.status()).as("create of an existing system").isEqualTo(412);
        assertThat(again.body()).isEqualTo("{\"error\":\"precondition_failed\"}");

        assertThat(put(id, gitlabBody(null), Map.of("If-Match", "\"Zx8Tq2LmWk93vNpA\"")).status()).as("stale etag").isEqualTo(412);
        BrokerClient.Response first = put(id, gitlabBody(null), Map.of("If-Match", etag));
        assertThat(first.status()).isEqualTo(200);
        BrokerClient.Response second = put(id, gitlabBody(null), Map.of("If-Match", etag));
        assertThat(second.status()).as("the etag was spent by the first write").isEqualTo(412);
        assertThat(put(id, gitlabBody(null), Map.of("If-Match", "not-an-etag")).status()).isEqualTo(400);
        assertThat(put(id, gitlabBody(null), Map.of("If-Match", etag, "If-None-Match", "*")).status()).isEqualTo(400);
        assertThat(get(id).header("ETag")).isEqualTo(first.header("ETag"));
    }

    @Test
    void reservedAndMalformedIdsAreRefused() {
        for (String reserved : List.of("gateway", "offboarding", "portal", "broker", "prometheus", "platform", "admin", "registry",
                "adapter", "internal", "ci")) {
            BrokerClient.Response response = create(reserved, gitlabBody(SECRET));
            assertThat(response.status()).as(reserved).isEqualTo(422);
            assertThat(Contracts.brokerSchemaErrors("SystemRejected", response.json())).isEmpty();
            assertThat(response.json().path("reason").stringValue()).isEqualTo("system_reserved");
            assertThat(get(reserved).status()).isEqualTo(404);
        }
        for (String malformed : List.of("Notes", "a", "1abc", "has-dash", "x".repeat(32))) {
            assertThat(create(malformed, gitlabBody(SECRET)).status()).as(malformed).isEqualTo(400);
        }
        assertThat(env.systems.findAll()).extracting(system -> system.id()).containsExactlyInAnyOrderElementsOf(STANDARD);
    }

    @Test
    void theClientSecretIsStoredInOpenBaoAndNeverReturnedOrLogged(CapturedOutput output) {
        String id = newId();
        String rid = TestTokens.newRequestId();
        BrokerClient.Response created = bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), rid,
                gitlabBody(SECRET), Map.of("If-None-Match", "*"));
        assertThat(created.status()).isEqualTo(200);

        assertThat(created.body()).doesNotContain(SECRET).doesNotContain("clientSecret\"");
        assertThat(get(id).body()).doesNotContain(SECRET);
        assertThat(list().body()).doesNotContain(SECRET);
        assertThat(storedSecret(id).path("client_secret").stringValue()).isEqualTo(SECRET);
        assertThat(jdbc.sql("select cast(t as text) from target_system t where id = :id").param("id", id).query(String.class).single())
                .as("not in the table").doesNotContain(SECRET);
        assertThat(output.getAll()).doesNotContain(SECRET);
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> assertThat(event.toString()).doesNotContain(SECRET));
    }

    @Test
    void aSecretIsRequiredWhenAnAddressOrTheClientChanges() {
        String id = newId();
        String base = env.gitlab.url();
        String authorize = "https://gitlab.test/oauth/authorize";
        String token = "https://gitlab.test/oauth/token";
        assertThat(create(id, gitlabBody(base, authorize, token, "client-one", null, "[]")).json().path("reason").stringValue())
                .as("a new system has no secret to keep").isEqualTo("client_secret_required");
        BrokerClient.Response created = create(id, gitlabBody(base, authorize, token, "client-one", SECRET, "[]"));
        assertThat(created.status()).isEqualTo(200);
        String etag = created.header("ETag");

        Map<String, String> changes = new java.util.LinkedHashMap<>();
        changes.put("baseUrl", gitlabBody(base + "/other", authorize, token, "client-one", null, "[]"));
        changes.put("authorizeUrl", gitlabBody(base, "https://gitlab.test/oauth/authorize2", token, "client-one", null, "[]"));
        changes.put("tokenUrl", gitlabBody(base, authorize, "https://gitlab.test/oauth/token2", "client-one", null, "[]"));
        changes.put("clientId", gitlabBody(base, authorize, token, "client-two", null, "[]"));
        changes.forEach((what, body) -> {
            BrokerClient.Response refused = put(id, body, Map.of("If-Match", etag));
            assertThat(refused.status()).as(what).isEqualTo(422);
            assertThat(Contracts.brokerSchemaErrors("SystemRejected", refused.json())).isEmpty();
            assertThat(refused.json().path("reason").stringValue()).as(what).isEqualTo("client_secret_required");
        });
        assertThat(storedSecret(id).path("client_secret").stringValue()).as("nothing was written").isEqualTo(SECRET);
        assertThat(get(id).header("ETag")).isEqualTo(etag);

        BrokerClient.Response unchanged = put(id, gitlabBody(base, authorize, token, "client-one", null, "[\"api\"]"),
                Map.of("If-Match", etag));
        assertThat(unchanged.status()).as("scopes are not an address").isEqualTo(200);
        assertThat(storedSecret(id).path("client_secret").stringValue()).isEqualTo(SECRET);

        String rotated = "test-only-rotated-client-secret-0002";
        BrokerClient.Response moved = put(id, gitlabBody(base + "/other", authorize, token, "client-one", rotated, "[]"),
                Map.of("If-Match", unchanged.header("ETag")));
        assertThat(moved.status()).isEqualTo(200);
        assertThat(storedSecret(id).path("client_secret").stringValue()).isEqualTo(rotated);
        assertThat(moved.body()).doesNotContain(rotated);
    }

    @Test
    void theConfigurationIsCheckedPerAdapterAndCredentialType() {
        String id = newId();
        String base = "\"baseUrl\":\"" + env.upstreamUrl() + "\"";
        Map<String, String> bodies = new java.util.LinkedHashMap<>();
        bodies.put("default_type_not_supported", "{" + base + ",\"adapter\":\"atlassian-dc\",\"supportedTypes\":[\"user-secret\"],"
                + "\"defaultType\":\"user-oauth\",\"secretScheme\":\"Bearer\"}");
        bodies.put("credential_types_mixed", "{" + base + ",\"adapter\":\"generic-rest\",\"supportedTypes\":"
                + "[\"service-account\",\"user-secret\"],\"defaultType\":\"service-account\",\"secretScheme\":\"Bearer\"}");
        bodies.put("adapter_type_mismatch", "{" + base + ",\"adapter\":\"generic-rest\",\"supportedTypes\":[\"user-secret\"],"
                + "\"defaultType\":\"user-secret\",\"secretScheme\":\"Bearer\"}");
        bodies.put("oauth_required", "{" + base + ",\"adapter\":\"gitlab\",\"supportedTypes\":[\"user-oauth\"],"
                + "\"defaultType\":\"user-oauth\",\"secretScheme\":\"Bearer\"}");
        bodies.put("secret_scheme_not_supported", "{" + base + ",\"adapter\":\"atlassian-dc\",\"supportedTypes\":[\"user-secret\"],"
                + "\"defaultType\":\"user-secret\",\"secretScheme\":\"Token\"}");
        bodies.forEach((reason, body) -> {
            BrokerClient.Response response = create(id, body);
            assertThat(response.status()).as(reason).isEqualTo(422);
            assertThat(Contracts.brokerSchemaErrors("SystemRejected", response.json())).isEmpty();
            assertThat(response.json().path("reason").stringValue()).isEqualTo(reason);
        });
        assertThat(create(id, "{" + base + ",\"adapter\":\"unknown\",\"supportedTypes\":[\"user-secret\"],"
                + "\"defaultType\":\"user-secret\",\"secretScheme\":\"Bearer\"}").status()).isEqualTo(400);
        assertThat(create(id, "{\"baseUrl\":\"ftp://x.test\",\"adapter\":\"atlassian-dc\",\"supportedTypes\":[\"user-secret\"],"
                + "\"defaultType\":\"user-secret\",\"secretScheme\":\"Bearer\"}").status()).isEqualTo(400);
        assertThat(create(id, "{" + base + ",\"adapter\":\"atlassian-dc\",\"supportedTypes\":[\"user-secret\"],"
                + "\"defaultType\":\"user-secret\",\"secretScheme\":\"Bearer\",\"extra\":1}").status()).isEqualTo(400);
        assertThat(get(id).status()).isEqualTo(404);

        BrokerClient.Response exchange = create(id, "{\"baseUrl\":\"" + env.upstreamUrl() + "\",\"adapter\":\"opensearch\","
                + "\"supportedTypes\":[\"token-exchange\"],\"defaultType\":\"token-exchange\",\"secretScheme\":\"Bearer\","
                + "\"oauth\":{\"clientId\":\"idp-client\",\"clientSecret\":\"" + SECRET + "\",\"authorizeUrl\":\"" + env.idp.tokenUrl()
                + "\",\"tokenUrl\":\"" + env.idp.tokenUrl() + "\",\"scopes\":[\"aud-scope\"]}}");
        assertThat(exchange.status()).isEqualTo(200);
        assertThat(registry.find(id)).hasValueSatisfying(system -> assertThat(system.tokenExchanger()).isPresent());
    }

    @Test
    void onlyAnAdministratorThroughTheBffMayChangeSystems(CapturedOutput output) {
        String id = newId();
        String rid = TestTokens.newRequestId();
        BrokerClient.Response notAdmin = bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffUser(adminSub, "alice"), rid,
                gitlabBody(SECRET), Map.of("If-None-Match", "*"));
        assertThat(notAdmin.status()).isEqualTo(403);
        assertThat(notAdmin.body()).isEqualTo("{\"error\":\"forbidden\"}");
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> {
            assertThat(event.path("event").stringValue()).isEqualTo("admin_change");
            assertThat(event.path("outcome").stringValue()).isEqualTo("denied");
            assertThat(event.path("reason").stringValue()).isEqualTo("not_admin");
        });
        assertThat(bff.send("GET", "/v1/admin/systems", tokens.bffUser(adminSub, "alice"), null, null).status()).isEqualTo(403);
        assertThat(bff.send("DELETE", "/v1/admin/systems/jira", tokens.bffUser(adminSub, "alice"), null, null).status()).isEqualTo(403);
        assertThat(bff.send("GET", "/v1/admin/systems", null, null, null).status()).isEqualTo(401);

        String gatewayRid = TestTokens.newRequestId();
        assertThat(gateway.send("GET", "/v1/admin/systems", tokens.gatewayUser(adminSub, "root", gatewayRid), gatewayRid, null).status())
                .as("the gateway certificate is not allowed on the admin operations").isEqualTo(403);
        BrokerClient offboarding = new BrokerClient(env.pki.clientContext(env.offboardingClient), port);
        assertThat(offboarding.send("GET", "/v1/admin/systems", null, null, null).status()).isEqualTo(403);
        assertThat(env.systems.find(id)).isEmpty();
        assertThat(registry.find("jira")).isPresent();
    }

    @Test
    void everyChangeLeavesAnAdminChangeEvent(CapturedOutput output) {
        String id = newId();
        String createRid = TestTokens.newRequestId();
        BrokerClient.Response created = bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), createRid,
                gitlabBody(SECRET), Map.of("If-None-Match", "*"));
        String updateRid = TestTokens.newRequestId();
        BrokerClient.Response updated = bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), updateRid,
                gitlabBody(env.gitlab.url(), "https://gitlab.test/oauth/authorize", "https://gitlab.test/oauth/token", "client-one",
                        null, "[\"api\"]"), Map.of("If-Match", created.header("ETag")));
        String refusedRid = TestTokens.newRequestId();
        bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), refusedRid, gitlabBody(SECRET),
                Map.of("If-Match", created.header("ETag")));
        String deleteRid = TestTokens.newRequestId();
        bff.send("DELETE", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), deleteRid, null);
        assertThat(updated.status()).isEqualTo(200);

        assertThat(AuditLines.of(output, createRid)).singleElement().satisfies(event -> {
            assertThat(event.path("event").stringValue()).isEqualTo("admin_change");
            assertThat(event.path("reason").stringValue()).isEqualTo("system_created");
            assertThat(event.path("outcome").stringValue()).isEqualTo("ok");
            assertThat(event.path("server").stringValue()).isEqualTo("mcp-" + id);
            assertThat(event.path("sub").stringValue()).isEqualTo(adminSub);
            assertThat(event.path("username").stringValue()).isEqualTo("root");
        });
        assertThat(AuditLines.of(output, updateRid)).singleElement()
                .satisfies(event -> assertThat(event.path("reason").stringValue()).isEqualTo("system_updated"));
        assertThat(AuditLines.of(output, refusedRid)).singleElement().satisfies(event -> {
            assertThat(event.path("outcome").stringValue()).isEqualTo("denied");
            assertThat(event.path("reason").stringValue()).isEqualTo("precondition_failed");
        });
        assertThat(AuditLines.of(output, deleteRid)).singleElement()
                .satisfies(event -> assertThat(event.path("reason").stringValue()).isEqualTo("system_deleted"));
    }

    @Test
    void aChangeIsVisibleToAnotherInstanceWithoutRestart() throws Exception {
        try (BrokerProcess second = BrokerProcess.start(env, PORT_SECOND_INSTANCE, Map.of())) {
            BrokerClient other = new BrokerClient(env.pki.clientContext(env.gatewayClient), second.port());
            String id = newId();
            assertThat(systemsOf(other)).doesNotContainKey(id);

            BrokerClient.Response created = create(id, gitlabBody(SECRET));
            assertThat(created.status()).isEqualTo(200);
            awaitSystems(other, systems -> systems.containsKey(id));
            assertThat(systemsOf(other).get(id).path("oauthScopes").get(0).stringValue()).isEqualTo("read_api");

            assertThat(put(id, gitlabBody(env.gitlab.url(), "https://gitlab.test/oauth/authorize", "https://gitlab.test/oauth/token",
                    "client-one", null, "[\"api\"]"), Map.of("If-Match", created.header("ETag"))).status()).isEqualTo(200);
            awaitSystems(other, systems -> systems.containsKey(id) && "api".equals(systems.get(id).path("oauthScopes").get(0).stringValue()));

            assertThat(delete(id).status()).isEqualTo(204);
            awaitSystems(other, systems -> !systems.containsKey(id));
            assertThat(second.alive()).isTrue();
        }
    }

    private Map<String, JsonNode> systemsOf(BrokerClient client) {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response response = client.send("GET", "/v1/systems", tokens.gatewayService(rid), rid, null);
        assertThat(response.status()).isEqualTo(200);
        Map<String, JsonNode> byId = new java.util.LinkedHashMap<>();
        response.json().forEach(system -> byId.put(system.path("system").stringValue(), system));
        return byId;
    }

    private void awaitSystems(BrokerClient client, java.util.function.Predicate<Map<String, JsonNode>> condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (System.nanoTime() < deadline) {
            if (condition.test(systemsOf(client))) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("the other instance did not pick up the change in 15 s: " + systemsOf(client).keySet());
    }

    @Test
    void deletingASystemRemovesTheConnectionsOfUsersAndPublishesInvalidation(CapturedOutput output) throws Exception {
        String id = newId();
        String base = "{\"baseUrl\":\"" + env.upstreamUrl() + "\",\"adapter\":\"atlassian-dc\",\"supportedTypes\":[\"user-secret\"],"
                + "\"defaultType\":\"user-secret\",\"secretScheme\":\"Bearer\"}";
        assertThat(create(id, base).status()).isEqualTo(200);
        String alice = UUID.randomUUID().toString();
        String bob = UUID.randomUUID().toString();
        for (String[] user : new String[][] {{alice, "alice", "alice-pat"}, {bob, "bob", "bob-pat"}}) {
            BrokerClient.Response connected = bff.send("PUT", "/v1/connections/" + id + "/secret", tokens.bffUser(user[0], user[1]),
                    null, "{\"secret\":\"" + user[2] + "\"}");
            assertThat(connected.status()).isEqualTo(200);
        }
        String aliceVersion = jdbc.sql("select secret_version from connection where sub = :sub and system = :system")
                .param("sub", alice).param("system", id).query(String.class).single();
        String alicePath = "secret/data/mcp/connections/" + new SecretKey(alice, id, aliceVersion).relativePath();
        assertThat(env.bao("GET", alicePath, null).statusCode()).isEqualTo(200);
        String rid = TestTokens.newRequestId();
        String resolveRid = TestTokens.newRequestId();
        assertThat(gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(alice, "alice", resolveRid), resolveRid,
                "{\"system\":\"" + id + "\"}").status()).isEqualTo(200);

        try (InvalidationListener invalidations = new InvalidationListener(env)) {
            BrokerClient.Response deleted = bff.send("DELETE", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), rid, null);
            assertThat(deleted.status()).isEqualTo(204);

            Set<String> subs = new java.util.HashSet<>();
            for (int i = 0; i < 2; i++) {
                JsonNode event = invalidations.next(5000);
                assertThat(event).as("credential.invalidated " + i).isNotNull();
                assertThat(event.path("system").stringValue()).isEqualTo(id);
                subs.add(event.path("sub").stringValue());
            }
            assertThat(subs).containsExactlyInAnyOrder(alice, bob);
        }
        assertThat(jdbc.sql("select count(*) from connection where system = :system").param("system", id).query(Long.class).single())
                .isZero();
        assertThat(env.bao("GET", alicePath, null).statusCode()).as("the stored value").isEqualTo(404);
        assertThat(env.bao("GET", alicePath.replace("/data/", "/metadata/"), null).statusCode()).as("every version").isEqualTo(404);

        String afterRid = TestTokens.newRequestId();
        BrokerClient.Response refused = gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(alice, "alice", afterRid),
                afterRid, "{\"system\":\"" + id + "\"}");
        assertThat(refused.status()).isEqualTo(422);
        assertThat(refused.body()).isEqualTo("{\"error\":\"system_not_configured\"}");
        assertThat(AuditLines.of(output, rid)).extracting(event -> event.path("event").stringValue() + ":" + event.path("reason").stringValue())
                .contains("admin_change:system_deleted", "connection_change:system_deleted");
    }

    @Test
    void aConnectionWhoseTypeTheSystemNoLongerTakesMustBeMadeAgain() {
        String id = newId();
        String userSecret = "{\"baseUrl\":\"" + env.upstreamUrl() + "\",\"adapter\":\"atlassian-dc\",\"supportedTypes\":[\"user-secret\"],"
                + "\"defaultType\":\"user-secret\",\"secretScheme\":\"Bearer\"}";
        BrokerClient.Response created = create(id, userSecret);
        String sub = UUID.randomUUID().toString();
        assertThat(bff.send("PUT", "/v1/connections/" + id + "/secret", tokens.bffUser(sub, "alice"), null,
                "{\"secret\":\"alice-pat\"}").status()).isEqualTo(200);

        String serviceKey = "{\"baseUrl\":\"" + env.upstreamUrl() + "\",\"adapter\":\"generic-rest\",\"supportedTypes\":"
                + "[\"service-account\"],\"defaultType\":\"service-account\",\"secretScheme\":\"Bearer\"}";
        assertThat(put(id, serviceKey, Map.of("If-Match", created.header("ETag"))).status()).isEqualTo(200);

        BrokerClient.Response connections = bff.send("GET", "/v1/connections", tokens.bffUser(sub, "alice"), null, null);
        assertThat(connections.json().get(0).path("status").stringValue()).isEqualTo("error");
    }
}
