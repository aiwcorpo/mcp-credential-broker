package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
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
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import pl.aiwcorpo.mcp.broker.system.SystemDefinition;
import tools.jackson.databind.JsonNode;

/**
 * C4 {@code /v1/admin/systems/{system}/service-account-key} (CC-251): the key goes to OpenBao and never comes back, the
 * writes need a fresh MFA, and the removal of a system takes the key with it.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class ServiceAccountKeyAdminIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final String BEARER_SYSTEM = "sakbearer";
    private static final String BASIC_SYSTEM = "sakbasic";
    private static final String KEY = "test-only-service-key-0001";
    private static final String PASSWORD = "test-only-service-password-0002";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @BeforeAll
    static void addSystems() {
        env.putSystem(serviceAccountSystem(BEARER_SYSTEM, CredentialScheme.BEARER));
        env.putSystem(serviceAccountSystem(BASIC_SYSTEM, CredentialScheme.BASIC));
        env.awaitSystemSync();
    }

    @AfterAll
    static void removeSystems() {
        env.removeSystem(BEARER_SYSTEM);
        env.removeSystem(BASIC_SYSTEM);
        env.awaitSystemSync();
    }

    @LocalServerPort
    int port;

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
    void removeKeys() {
        for (String system : List.of(BEARER_SYSTEM, BASIC_SYSTEM)) {
            env.bao("DELETE", "secret/metadata/mcp/service-accounts/" + system, null);
        }
    }

    private static SystemDefinition serviceAccountSystem(String id, CredentialScheme scheme) {
        return new SystemDefinition(id, URI.create(env.upstreamUrl()), "generic-rest", null, List.of(CredentialType.SERVICE_ACCOUNT),
                CredentialType.SERVICE_ACCOUNT, scheme, null, null, null, null, null, null, SystemDefinition.newToken(),
                SystemDefinition.newToken());
    }

    private String admin() {
        return tokens.bffAdmin(adminSub, "a.admin");
    }

    private BrokerClient.Response getKey(String system) {
        return bff.send("GET", keyPath(system), admin(), TestTokens.newRequestId(), null);
    }

    private BrokerClient.Response putKey(String system, String body) {
        return putKey(system, body, admin(), TestTokens.newRequestId());
    }

    private BrokerClient.Response putKey(String system, String body, String token, String requestId) {
        return bff.send("PUT", keyPath(system), token, requestId, body);
    }

    private BrokerClient.Response deleteKey(String system, String token, String requestId) {
        return bff.send("DELETE", keyPath(system), token, requestId, null);
    }

    private static String keyPath(String system) {
        return "/v1/admin/systems/" + system + "/service-account-key";
    }

    private BrokerClient.Response resolve(String system) {
        String rid = TestTokens.newRequestId();
        return gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(UUID.randomUUID().toString(), "test-user", rid, "get_ticket"),
                rid, "{\"system\":\"" + system + "\"}");
    }

    private static String bearerBody(String key, String expiresAt) {
        return "{\"value\":\"" + key + "\"" + (expiresAt == null ? "" : ",\"expiresAt\":\"" + expiresAt + "\"") + "}";
    }

    private JsonNode systemView(String system) {
        return bff.send("GET", "/v1/admin/systems/" + system, admin(), TestTokens.newRequestId(), null).json();
    }

    // Write-only -------------------------------------------------------------------------------------------

    @Test
    void theStatusNeverCarriesTheKeyAndTheKeyIsWhatResolveHandsOut(CapturedOutput output) {
        BrokerClient.Response before = getKey(BEARER_SYSTEM);
        assertThat(before.status()).isEqualTo(200);
        assertThat(before.json().propertyNames()).containsExactlyInAnyOrder("system", "set");
        assertThat(before.json().path("set").booleanValue()).isFalse();

        String expiry = Instant.now().plusSeconds(86_400).toString();
        BrokerClient.Response stored = putKey(BEARER_SYSTEM, bearerBody(KEY, expiry));
        assertThat(stored.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("ServiceAccountKeyStatus", stored.json())).isEmpty();
        assertThat(stored.header("Cache-Control")).isEqualTo("no-store");

        BrokerClient.Response read = getKey(BEARER_SYSTEM);
        assertThat(read.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("ServiceAccountKeyStatus", read.json())).isEmpty();
        assertThat(read.json().path("system").stringValue()).isEqualTo(BEARER_SYSTEM);
        assertThat(read.json().path("set").booleanValue()).isTrue();
        assertThat(read.json().path("kvVersion").intValue()).isEqualTo(1);
        assertThat(read.json().path("expired").booleanValue()).isFalse();
        assertThat(read.json().path("updatedBy").stringValue()).isEqualTo("a.admin");
        assertThat(Instant.parse(read.json().path("expiresAt").stringValue())).isBeforeOrEqualTo(Instant.parse(expiry));
        assertThat(read.json()).isEqualTo(stored.json().deepCopy());
        for (BrokerClient.Response response : List.of(stored, read)) {
            assertThat(response.body()).doesNotContain(KEY);
        }

        BrokerClient.Response resolved = resolve(BEARER_SYSTEM);
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(resolved.json().path("value").stringValue()).isEqualTo(KEY);
        assertThat(output.getAll()).doesNotContain(KEY);
    }

    @Test
    void anEntryOnlyTheOperatorWroteShowsNoWriterAndTheListSaysSet() {
        assertThat(env.bao("POST", "secret/data/mcp/service-accounts/" + BEARER_SYSTEM,
                "{\"data\":{\"value\":\"" + KEY + "\"}}").statusCode()).isEqualTo(200);

        JsonNode status = getKey(BEARER_SYSTEM).json();
        assertThat(status.path("set").booleanValue()).isTrue();
        assertThat(status.has("updatedBy")).isFalse();
        assertThat(status.has("expiresAt")).isFalse();

        JsonNode listed = bff.send("GET", "/v1/admin/systems", admin(), TestTokens.newRequestId(), null).json();
        JsonNode view = listed.valueStream().filter(s -> BEARER_SYSTEM.equals(s.path("system").stringValue())).findFirst().orElseThrow();
        assertThat(Contracts.brokerSchemaErrors("SystemAdminView", view)).isEmpty();
        assertThat(view.path("serviceAccountKey").path("state").stringValue()).isEqualTo("set");
        listed.valueStream().filter(s -> "jira".equals(s.path("system").stringValue()))
                .forEach(jira -> assertThat(jira.has("serviceAccountKey")).as("not a service-account system").isFalse());
    }

    // MFA and authorization ------------------------------------------------------------------------------------

    @Test
    void aWriteAndADeleteNeedAFreshMfaButAReadDoesNot(CapturedOutput output) {
        assertThat(putKey(BEARER_SYSTEM, bearerBody(KEY, null)).status()).isEqualTo(200);
        String stale = tokens.bffAdmin(adminSub, "a.admin", Instant.now().minusSeconds(301));
        String recentPasswordOnly = tokens.bffAdmin(adminSub, "a.admin", Instant.now().minusSeconds(20), Map.of("amr", List.of("pwd")));

        for (String token : List.of(stale, recentPasswordOnly)) {
            String rid = TestTokens.newRequestId();
            BrokerClient.Response put = putKey(BEARER_SYSTEM, bearerBody("test-only-other-key-9999", null), token, rid);
            assertThat(put.status()).isEqualTo(401);
            assertThat(put.body()).isEqualTo("{\"error\":\"step_up_required\"}");
            assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> {
                assertThat(event.path("outcome").stringValue()).isEqualTo("denied");
                assertThat(event.path("reason").stringValue()).isEqualTo("step_up_required");
            });
            BrokerClient.Response delete = deleteKey(BEARER_SYSTEM, token, null);
            assertThat(delete.status()).isEqualTo(401);
            assertThat(delete.body()).isEqualTo("{\"error\":\"step_up_required\"}");
            assertThat(bff.send("GET", keyPath(BEARER_SYSTEM), token, null, null).status()).as("a read needs no fresh MFA").isEqualTo(200);
        }
        assertThat(getKey(BEARER_SYSTEM).json().path("kvVersion").intValue()).as("nothing was written or removed").isEqualTo(1);
        assertThat(resolve(BEARER_SYSTEM).json().path("value").stringValue()).isEqualTo(KEY);
    }

    @Test
    void aCallerThatIsNotAnAdministratorIsRefused(CapturedOutput output) {
        String user = tokens.bffUser(UUID.randomUUID().toString(), "test-user");
        String rid = TestTokens.newRequestId();
        assertThat(bff.send("GET", keyPath(BEARER_SYSTEM), user, null, null).status()).isEqualTo(403);
        assertThat(putKey(BEARER_SYSTEM, bearerBody(KEY, null), user, rid).status()).isEqualTo(403);
        assertThat(deleteKey(BEARER_SYSTEM, user, null).status()).isEqualTo(403);
        assertThat(AuditLines.of(output, rid)).singleElement()
                .satisfies(event -> assertThat(event.path("reason").stringValue()).isEqualTo("not_admin"));
        assertThat(getKey(BEARER_SYSTEM).json().path("set").booleanValue()).isFalse();
    }

    @Test
    void onlyThePortalBffMayCall() {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response response = gateway.send("GET", keyPath(BEARER_SYSTEM), admin(), rid, null);
        assertThat(response.status()).isIn(403, 404);
    }

    // Which key fits which system -------------------------------------------------------------------------

    @Test
    void aSystemThatTakesNoServiceAccountKeyRefusesIt(CapturedOutput output) {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response refused = putKey("jira", bearerBody(KEY, null), admin(), rid);
        assertThat(refused.status()).isEqualTo(422);
        assertThat(Contracts.brokerSchemaErrors("ServiceAccountKeyRejected", refused.json())).isEmpty();
        assertThat(refused.json().path("error").stringValue()).isEqualTo("service_account_key_rejected");
        assertThat(refused.json().path("reason").stringValue()).isEqualTo("system_not_service_account");
        assertThat(refused.body()).doesNotContain(KEY);
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> {
            assertThat(event.path("outcome").stringValue()).isEqualTo("denied");
            assertThat(event.path("reason").stringValue()).isEqualTo("system_not_service_account");
            assertThat(event.has("kvVersion")).isFalse();
        });
        assertThat(env.bao("GET", "secret/data/mcp/service-accounts/jira", null).statusCode()).as("nothing was written").isEqualTo(404);
    }

    @Test
    void aSystemThatIsNotConfiguredIsNotFound() {
        assertThat(getKey("nosuchsystem").status()).isEqualTo(404);
        assertThat(putKey("nosuchsystem", bearerBody(KEY, null)).status()).isEqualTo(404);
        assertThat(deleteKey("nosuchsystem", admin(), null).status()).isEqualTo(404);
    }

    @Test
    void aLeftoverKeyOfASystemThatIsNoServiceAccountAnymoreCanBeSeenAndRemoved() {
        assertThat(env.bao("POST", "secret/data/mcp/service-accounts/jira", "{\"data\":{\"value\":\"" + KEY + "\"}}").statusCode()).isEqualTo(200);
        try {
            assertThat(getKey("jira").json().path("set").booleanValue()).isTrue();
            assertThat(deleteKey("jira", admin(), null).status()).isEqualTo(204);
            assertThat(getKey("jira").json().path("set").booleanValue()).isFalse();
        } finally {
            env.bao("DELETE", "secret/metadata/mcp/service-accounts/jira", null);
        }
    }

    @Test
    void aBasicSystemTakesTheLoginPairOrTheBase64AndNothingElse() {
        assertThat(putKey(BASIC_SYSTEM, "{\"username\":\"svc-mcp\",\"password\":\"" + PASSWORD + "\"}").status()).isEqualTo(200);
        BrokerClient.Response resolved = resolve(BASIC_SYSTEM);
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(resolved.json().path("scheme").stringValue()).isEqualTo("Basic");
        assertThat(new String(java.util.Base64.getDecoder().decode(resolved.json().path("value").stringValue()),
                java.nio.charset.StandardCharsets.UTF_8)).isEqualTo("svc-mcp:" + PASSWORD);

        String encoded = java.util.Base64.getEncoder().encodeToString("svc-two:pw".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertThat(putKey(BASIC_SYSTEM, bearerBody(encoded, null)).status()).isEqualTo(200);
        assertThat(resolve(BASIC_SYSTEM).json().path("value").stringValue()).isEqualTo(encoded);

        String noColon = java.util.Base64.getEncoder().encodeToString("svc-without-colon".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        for (String notBasic : List.of("test-only-not-base64!", noColon)) {
            BrokerClient.Response refused = putKey(BASIC_SYSTEM, bearerBody(notBasic, null));
            assertThat(refused.status()).as(notBasic).isEqualTo(422);
            assertThat(refused.json().path("reason").stringValue()).isEqualTo("value_not_basic_credential");
            assertThat(refused.body()).doesNotContain(notBasic);
        }
        assertThat(getKey(BASIC_SYSTEM).json().path("kvVersion").intValue()).as("refusals wrote nothing").isEqualTo(2);
    }

    @Test
    void aLoginPairForANonBasicSystemIsRefused() {
        BrokerClient.Response refused = putKey(BEARER_SYSTEM, "{\"username\":\"svc-mcp\",\"password\":\"" + PASSWORD + "\"}");
        assertThat(refused.status()).isEqualTo(422);
        assertThat(refused.json().path("reason").stringValue()).isEqualTo("basic_scheme_required");
        assertThat(refused.body()).doesNotContain(PASSWORD);
        assertThat(getKey(BEARER_SYSTEM).json().path("set").booleanValue()).isFalse();
    }

    @Test
    void aBodyOfTheWrongShapeIsABadRequestThatEchoesNothing() {
        List<String> bodies = List.of("{}", "{\"value\":\"" + KEY + "\",\"username\":\"u\",\"password\":\"" + PASSWORD + "\"}",
                "{\"username\":\"u\"}", "{\"value\":\"two words " + KEY + "\"}", "{\"username\":\"u:v\",\"password\":\"" + PASSWORD + "\"}",
                "{\"value\":\"" + KEY + "\",\"extra\":1}", "{\"value\":\"" + KEY + "\",\"expiresAt\":\"tomorrow\"}");
        for (String body : bodies) {
            BrokerClient.Response refused = putKey(BASIC_SYSTEM, body);
            assertThat(refused.status()).as(body).isEqualTo(400);
            assertThat(refused.body()).as(body).doesNotContain(KEY).doesNotContain(PASSWORD);
        }
        assertThat(getKey(BASIC_SYSTEM).json().path("set").booleanValue()).isFalse();
    }

    // Expiry and versions ----------------------------------------------------------------------------------

    @Test
    void anExpiryInThePastIsRefusedAndAnExpiredEntryIsMarked() {
        BrokerClient.Response refused = putKey(BEARER_SYSTEM, bearerBody(KEY, Instant.now().minusSeconds(5).toString()));
        assertThat(refused.status()).isEqualTo(422);
        assertThat(refused.json().path("reason").stringValue()).isEqualTo("expires_at_in_past");
        assertThat(getKey(BEARER_SYSTEM).json().path("set").booleanValue()).isFalse();

        String past = Instant.now().minusSeconds(60).toString();
        assertThat(env.bao("POST", "secret/data/mcp/service-accounts/" + BEARER_SYSTEM,
                "{\"data\":{\"value\":\"" + KEY + "\",\"expires_at\":\"" + past + "\"}}").statusCode()).isEqualTo(200);
        JsonNode expired = getKey(BEARER_SYSTEM).json();
        assertThat(expired.path("expired").booleanValue()).isTrue();
        assertThat(Instant.parse(expired.path("expiresAt").stringValue())).isBefore(Instant.now());
        assertThat(resolve(BEARER_SYSTEM).status()).as("resolve fails closed for it").isEqualTo(503);
    }

    @Test
    void theLastWriteWinsAndAnExpiryIsNotKeptByAWriteWithoutOne() {
        assertThat(putKey(BEARER_SYSTEM, bearerBody(KEY, Instant.now().plusSeconds(3600).toString())).json().path("kvVersion").intValue())
                .isEqualTo(1);
        BrokerClient.Response second = putKey(BEARER_SYSTEM, bearerBody("test-only-service-key-0002", null));
        assertThat(second.json().path("kvVersion").intValue()).isEqualTo(2);
        assertThat(second.json().has("expiresAt")).isFalse();
        assertThat(getKey(BEARER_SYSTEM).json().has("expiresAt")).isFalse();
        assertThat(resolve(BEARER_SYSTEM).json().path("value").stringValue()).isEqualTo("test-only-service-key-0002");
    }

    // Audit ------------------------------------------------------------------------------------------------

    @Test
    void theAuditEventsCarryTheVersionAndTheExpiryButNeverTheKey(CapturedOutput output) {
        String expiry = Instant.now().plusSeconds(86_400).toString();
        String setRid = TestTokens.newRequestId();
        assertThat(putKey(BASIC_SYSTEM, "{\"username\":\"svc-login-0003\",\"password\":\"" + PASSWORD + "\",\"expiresAt\":\"" + expiry + "\"}",
                admin(), setRid).status()).isEqualTo(200);
        String deleteRid = TestTokens.newRequestId();
        assertThat(deleteKey(BASIC_SYSTEM, admin(), deleteRid).status()).isEqualTo(204);
        String noneRid = TestTokens.newRequestId();
        assertThat(deleteKey(BASIC_SYSTEM, admin(), noneRid).status()).as("also when there was none").isEqualTo(204);

        assertThat(AuditLines.of(output, setRid)).singleElement().satisfies(event -> {
            assertThat(event.path("event").stringValue()).isEqualTo("admin_change");
            assertThat(event.path("reason").stringValue()).isEqualTo("service_account_key_set");
            assertThat(event.path("outcome").stringValue()).isEqualTo("ok");
            assertThat(event.path("server").stringValue()).isEqualTo("mcp-" + BASIC_SYSTEM);
            assertThat(event.path("sub").stringValue()).isEqualTo(adminSub);
            assertThat(event.path("username").stringValue()).isEqualTo("a.admin");
            assertThat(event.path("kvVersion").intValue()).isEqualTo(1);
            assertThat(Instant.parse(event.path("expiresAt").stringValue())).isBeforeOrEqualTo(Instant.parse(expiry));
        });
        assertThat(AuditLines.of(output, deleteRid)).singleElement().satisfies(event -> {
            assertThat(event.path("reason").stringValue()).isEqualTo("service_account_key_deleted");
            assertThat(event.path("kvVersion").intValue()).isEqualTo(1);
            assertThat(event.has("expiresAt")).isFalse();
        });
        assertThat(AuditLines.of(output, noneRid)).singleElement().satisfies(event -> {
            assertThat(event.path("reason").stringValue()).isEqualTo("service_account_key_deleted");
            assertThat(event.has("kvVersion")).as("no entry, no version").isFalse();
        });
        assertThat(output.getAll()).doesNotContain(PASSWORD).doesNotContain("svc-login-0003");
    }

    @Test
    void deletingTheKeyRemovesEveryVersionAndResolveFailsClosed() {
        putKey(BEARER_SYSTEM, bearerBody(KEY, null));
        putKey(BEARER_SYSTEM, bearerBody("test-only-service-key-0002", null));
        assertThat(env.bao("GET", "secret/metadata/mcp/service-accounts/" + BEARER_SYSTEM, null).statusCode()).isEqualTo(200);

        assertThat(deleteKey(BEARER_SYSTEM, admin(), null).status()).isEqualTo(204);

        assertThat(env.bao("GET", "secret/metadata/mcp/service-accounts/" + BEARER_SYSTEM, null).statusCode()).isEqualTo(404);
        assertThat(getKey(BEARER_SYSTEM).json().path("set").booleanValue()).isFalse();
        assertThat(resolve(BEARER_SYSTEM).status()).isEqualTo(503);
        assertThat(deleteKey(BEARER_SYSTEM, admin(), null).status()).as("idempotent").isEqualTo(204);
    }

    // Removal of the system --------------------------------------------------------------------------------

    @Test
    void removingTheSystemRemovesItsKeyToo(CapturedOutput output) {
        String id = "n" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        String body = "{\"baseUrl\":\"" + env.upstreamUrl() + "\",\"adapter\":\"generic-rest\",\"supportedTypes\":[\"service-account\"],"
                + "\"defaultType\":\"service-account\",\"secretScheme\":\"Bearer\"}";
        BrokerClient.Response created = bff.send("PUT", "/v1/admin/systems/" + id, admin(), TestTokens.newRequestId(), body,
                Map.of("If-None-Match", "*"));
        assertThat(created.status()).isEqualTo(200);
        assertThat(created.json().path("serviceAccountKey").path("state").stringValue()).isEqualTo("missing");
        assertThat(Contracts.brokerSchemaErrors("SystemAdminView", created.json())).isEmpty();

        String expiry = Instant.now().plusSeconds(86_400).toString();
        assertThat(putKey(id, bearerBody(KEY, expiry)).status()).isEqualTo(200);
        assertThat(putKey(id, bearerBody(KEY, expiry)).status()).isEqualTo(200);
        JsonNode summary = systemView(id).path("serviceAccountKey");
        assertThat(summary.path("state").stringValue()).isEqualTo("set");
        assertThat(summary.path("expired").booleanValue()).isFalse();
        assertThat(Instant.parse(summary.path("expiresAt").stringValue())).isBeforeOrEqualTo(Instant.parse(expiry));
        assertThat(summary.propertyNames()).as("no version and no author in the summary").containsExactlyInAnyOrder("state", "expiresAt", "expired");

        String rid = TestTokens.newRequestId();
        BrokerClient.Response gone = bff.send("DELETE", "/v1/admin/systems/" + id, admin(), rid, null,
                Map.of("If-Match", bff.send("GET", "/v1/admin/systems/" + id, admin(), null, null).header("ETag")));
        assertThat(gone.status()).isEqualTo(204);

        assertThat(env.bao("GET", "secret/metadata/mcp/service-accounts/" + id, null).statusCode()).as("every version is gone").isEqualTo(404);
        List<String> reasons = AuditLines.of(output, rid).stream().map(event -> event.path("reason").stringValue()).collect(Collectors.toList());
        assertThat(reasons).contains("system_deleted", "service_account_key_deleted");
        assertThat(AuditLines.of(output, rid).stream().filter(event -> "service_account_key_deleted".equals(event.path("reason").stringValue())).findFirst())
                .hasValueSatisfying(event -> {
                    assertThat(event.path("kvVersion").intValue()).isEqualTo(2);
                    assertThat(event.path("server").stringValue()).isEqualTo("mcp-" + id);
                });
        assertThat(output.getAll()).doesNotContain(KEY);
    }

    @Test
    void removingASystemThatNeverHadAKeyWritesNoKeyEvent(CapturedOutput output) {
        String id = "n" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        String body = "{\"baseUrl\":\"" + env.upstreamUrl() + "\",\"adapter\":\"generic-rest\",\"supportedTypes\":[\"service-account\"],"
                + "\"defaultType\":\"service-account\",\"secretScheme\":\"Bearer\"}";
        BrokerClient.Response created = bff.send("PUT", "/v1/admin/systems/" + id, admin(), TestTokens.newRequestId(), body,
                Map.of("If-None-Match", "*"));
        assertThat(created.status()).isEqualTo(200);
        String rid = TestTokens.newRequestId();
        assertThat(bff.send("DELETE", "/v1/admin/systems/" + id, admin(), rid, null, Map.of("If-Match", created.header("ETag"))).status())
                .isEqualTo(204);
        assertThat(AuditLines.of(output, rid)).extracting(event -> event.path("reason").stringValue())
                .containsExactly("system_deleted");
    }

    @Test
    void anIdWithoutASystemDeletesNoKey() {
        assertThat(env.bao("POST", "secret/data/mcp/service-accounts/nosuchsystem", "{\"data\":{\"value\":\"" + KEY + "\"}}").statusCode())
                .isEqualTo(200);
        try {
            assertThat(bff.send("DELETE", "/v1/admin/systems/nosuchsystem", admin(), null, null).status()).isEqualTo(204);
            assertThat(env.bao("GET", "secret/data/mcp/service-accounts/nosuchsystem", null).statusCode()).isEqualTo(200);
        } finally {
            env.bao("DELETE", "secret/metadata/mcp/service-accounts/nosuchsystem", null);
        }
    }

    // OpenBao unavailable ------------------------------------------------------------------------------------

    @Test
    void withOpenBaoGoneTheViewsSayUnknownAndTheOperationsFailClosed(CapturedOutput output) throws Exception {
        assertThat(putKey(BEARER_SYSTEM, bearerBody(KEY, null)).status()).isEqualTo(200);
        String putRid = TestTokens.newRequestId();
        String deleteRid = TestTokens.newRequestId();

        BrokerClient.Response view;
        BrokerClient.Response read;
        BrokerClient.Response put;
        BrokerClient.Response delete;
        env.openbao.getDockerClient().pauseContainerCmd(env.openbao.getContainerId()).exec();
        try {
            view = bff.send("GET", "/v1/admin/systems/" + BEARER_SYSTEM, admin(), TestTokens.newRequestId(), null);
            read = getKey(BEARER_SYSTEM);
            put = putKey(BEARER_SYSTEM, bearerBody("test-only-service-key-0009", null), admin(), putRid);
            delete = deleteKey(BEARER_SYSTEM, admin(), deleteRid);
        } finally {
            env.openbao.getDockerClient().unpauseContainerCmd(env.openbao.getContainerId()).exec();
        }

        assertThat(view.status()).as("the read of a system survives a store that does not answer").isEqualTo(200);
        assertThat(view.json().path("serviceAccountKey").path("state").stringValue()).isEqualTo("unknown");
        assertThat(Contracts.brokerSchemaErrors("SystemAdminView", view.json())).isEmpty();
        for (BrokerClient.Response failed : List.of(read, put, delete)) {
            assertThat(failed.status()).isEqualTo(503);
            assertThat(failed.body()).isEqualTo("{\"error\":\"upstream_unavailable\"}");
        }
        assertThat(AuditLines.of(output, putRid)).singleElement().satisfies(event -> {
            assertThat(event.path("outcome").stringValue()).isEqualTo("error");
            assertThat(event.path("reason").stringValue()).isEqualTo("secret_store_unavailable");
        });
        assertThat(AuditLines.of(output, deleteRid)).singleElement()
                .satisfies(event -> assertThat(event.path("reason").stringValue()).isEqualTo("secret_store_unavailable"));
        assertThat(output.getAll()).doesNotContain("test-only-service-key-0009");

        long deadline = System.currentTimeMillis() + 15_000;
        while (getKey(BEARER_SYSTEM).status() != 200 && System.currentTimeMillis() < deadline) {
            Thread.sleep(500);
        }
        JsonNode after = getKey(BEARER_SYSTEM).json();
        assertThat(after.path("kvVersion").intValue()).as("nothing was written or removed while it was gone").isEqualTo(1);
        assertThat(systemViewState(BEARER_SYSTEM)).isEqualTo("set");
    }

    private String systemViewState(String system) {
        return systemView(system).path("serviceAccountKey").path("state").stringValue();
    }
}
