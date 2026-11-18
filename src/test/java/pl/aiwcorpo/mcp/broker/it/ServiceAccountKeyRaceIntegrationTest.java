package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.mockito.ArgumentMatchers.any;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;
import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;
import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import pl.aiwcorpo.mcp.broker.system.SystemRepository;

/**
 * A key must not outlive its system, whichever way a write of the key and the removal of the system interleave (CC-251).
 * The store is a spy so that a test can run one step in the middle of the other.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class ServiceAccountKeyRaceIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final String KEY = "test-only-service-key-0007";
    private static final String BODY_TEMPLATE = "{\"baseUrl\":\"%s\",\"adapter\":\"generic-rest\",\"supportedTypes\":[\"service-account\"],"
            + "\"defaultType\":\"service-account\",\"secretScheme\":\"Bearer\"}";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @LocalServerPort
    int port;

    @MockitoSpyBean
    SystemRepository repository;

    @MockitoSpyBean
    ServiceAccountKeys keys;

    BrokerClient bff;
    final TestTokens tokens = env.tokens;
    final String adminSub = UUID.randomUUID().toString();

    @BeforeEach
    void client() {
        bff = new BrokerClient(env.pki.clientContext(env.bffClient), port);
    }

    @AfterEach
    void restore() {
        reset(keys, repository);
    }

    private String admin() {
        return tokens.bffAdmin(adminSub, "a.admin");
    }

    private String createSystem() {
        String id = "n" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        BrokerClient.Response created = bff.send("PUT", "/v1/admin/systems/" + id, admin(), TestTokens.newRequestId(),
                BODY_TEMPLATE.formatted(env.upstreamUrl()), Map.of("If-None-Match", "*"));
        assertThat(created.status()).isEqualTo(200);
        return id;
    }

    private BrokerClient.Response putKey(String id) {
        return bff.send("PUT", "/v1/admin/systems/" + id + "/service-account-key", admin(), TestTokens.newRequestId(),
                "{\"value\":\"" + KEY + "\"}");
    }

    private BrokerClient.Response deleteSystem(String id, String rid) {
        String etag = bff.send("GET", "/v1/admin/systems/" + id, admin(), null, null).header("ETag");
        return bff.send("DELETE", "/v1/admin/systems/" + id, admin(), rid, null, Map.of("If-Match", etag));
    }

    private static int keyEntryStatus(String id) {
        return env.bao("GET", "secret/metadata/mcp/service-accounts/" + id, null).statusCode();
    }

    @Test
    void aKeyWrittenAfterTheSystemIsGoneLeavesNothingBehind() {
        String id = createSystem();
        assertThat(deleteSystem(id, null).status()).isEqualTo(204);

        assertThat(putKey(id).status()).isEqualTo(404);

        assertThat(keyEntryStatus(id)).isEqualTo(404);
    }

    @Test
    void aSystemDeletedWhileTheKeyIsBeingWrittenTakesTheEntryJustWrittenAway(CapturedOutput output) {
        String id = createSystem();
        doAnswer(invocation -> {
            Object written = invocation.callRealMethod();
            assertThat(repository.delete(id, repository.find(id).orElseThrow().etag())).isTrue();
            return written;
        }).when(keys).write(eq(id), org.mockito.ArgumentMatchers.any());

        BrokerClient.Response put = putKey(id);

        assertThat(put.status()).isEqualTo(404);
        assertThat(put.body()).doesNotContain(KEY);
        assertThat(keyEntryStatus(id)).as("the entry written a moment ago is removed again").isEqualTo(404);
        assertThat(output.getAll()).doesNotContain(KEY);
    }

    @Test
    void theKeyIsRemovedOnlyAfterTheRowIsGone() {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);
        AtomicReference<Boolean> rowGoneWhenTheKeyWasRemoved = new AtomicReference<>();
        doAnswer(invocation -> {
            rowGoneWhenTheKeyWasRemoved.set(repository.find(id).isEmpty());
            return invocation.callRealMethod();
        }).when(keys).remove(eq(id));

        assertThat(deleteSystem(id, null).status()).isEqualTo(204);

        assertThat(rowGoneWhenTheKeyWasRemoved.get()).isTrue();
        assertThat(keyEntryStatus(id)).isEqualTo(404);
    }

    @Test
    void aKeyWrittenBetweenTheRowDeleteAndTheKeyRemovalIsRemovedWithIt() {
        String id = createSystem();
        doAnswer(invocation -> {
            env.bao("POST", "secret/data/mcp/service-accounts/" + id, "{\"data\":{\"value\":\"" + KEY + "\"}}");
            return invocation.callRealMethod();
        }).when(keys).remove(eq(id));

        assertThat(deleteSystem(id, null).status()).isEqualTo(204);

        assertThat(keyEntryStatus(id)).isEqualTo(404);
    }

    @Test
    void aFailedKeyRemovalAfterTheRowDeleteIsAuditedAndTheSystemStaysDeleted(CapturedOutput output) {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);
        doThrow(new SecretStoreUnavailableException("secret store unreachable: test")).when(keys).remove(eq(id));
        String rid = TestTokens.newRequestId();

        BrokerClient.Response deleted = deleteSystem(id, rid);

        assertThat(deleted.status()).isEqualTo(503);
        assertThat(deleted.body()).isEqualTo("{\"error\":\"upstream_unavailable\"}");
        assertThat(bff.send("GET", "/v1/admin/systems/" + id, admin(), null, null).status()).as("not resurrected").isEqualTo(404);
        List<String> outcomes = AuditLines.of(output, rid).stream()
                .map(event -> event.path("reason").stringValue() + ":" + event.path("outcome").stringValue()).toList();
        assertThat(outcomes).containsExactly("system_deleted:ok", "secret_store_unavailable:error");
        assertThat(output.getAll()).doesNotContain(KEY);
    }

    private static String newId() {
        return "n" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
    }

    private static void leaveOrphan(String id) {
        assertThat(env.bao("POST", "secret/data/mcp/service-accounts/" + id, "{\"data\":{\"value\":\"" + KEY + "\"}}").statusCode()).isEqualTo(200);
    }

    private BrokerClient.Response create(String id, String rid) {
        return bff.send("PUT", "/v1/admin/systems/" + id, admin(), rid, BODY_TEMPLATE.formatted(env.upstreamUrl()),
                Map.of("If-None-Match", "*"));
    }

    @Test
    void aNewSystemNeverInheritsAKeyLeftUnderItsId(CapturedOutput output) {
        String id = newId();
        leaveOrphan(id);
        String rid = TestTokens.newRequestId();

        BrokerClient.Response created = create(id, rid);

        assertThat(created.status()).isEqualTo(200);
        assertThat(created.json().path("serviceAccountKey").path("state").stringValue()).isEqualTo("missing");
        assertThat(keyEntryStatus(id)).as("every version of the orphan is gone").isEqualTo(404);
        assertThat(AuditLines.of(output, rid)).extracting(event -> event.path("reason").stringValue())
                .contains("service_account_key_deleted", "system_created");
        assertThat(output.getAll()).doesNotContain(KEY);
    }

    @Test
    void aSystemIsNotCreatedOnTopOfAKeyThatCannotBeRemoved(CapturedOutput output) {
        String id = newId();
        leaveOrphan(id);
        doThrow(new SecretStoreUnavailableException("secret store unreachable: test")).when(keys).remove(eq(id));
        String rid = TestTokens.newRequestId();

        BrokerClient.Response created = create(id, rid);

        assertThat(created.status()).isEqualTo(503);
        assertThat(created.body()).isEqualTo("{\"error\":\"upstream_unavailable\"}");
        assertThat(repository.find(id)).as("no system was created").isEmpty();
        assertThat(keyEntryStatus(id)).as("the orphan is still there").isEqualTo(200);
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> {
            assertThat(event.path("outcome").stringValue()).isEqualTo("error");
            assertThat(event.path("reason").stringValue()).isEqualTo("secret_store_unavailable");
        });
        assertThat(output.getAll()).doesNotContain(KEY);
        reset(keys);
        env.bao("DELETE", "secret/metadata/mcp/service-accounts/" + id, null);
    }

    @Test
    void anOperatorCleansUpAnOrphanThroughTheKeyEndpointOfAnUnconfiguredSystem(CapturedOutput output) {
        String id = newId();
        assertThat(deleteKey(id, TestTokens.newRequestId()).status()).as("nothing there").isEqualTo(404);
        leaveOrphan(id);
        String rid = TestTokens.newRequestId();

        assertThat(deleteKey(id, rid).status()).isEqualTo(204);

        assertThat(keyEntryStatus(id)).isEqualTo(404);
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> {
            assertThat(event.path("reason").stringValue()).isEqualTo("service_account_key_deleted");
            assertThat(event.path("kvVersion").intValue()).isEqualTo(1);
        });
        assertThat(deleteKey(id, TestTokens.newRequestId()).status()).isEqualTo(404);
        assertThat(output.getAll()).doesNotContain(KEY);
    }

    private BrokerClient.Response deleteKey(String id, String rid) {
        return bff.send("DELETE", "/v1/admin/systems/" + id + "/service-account-key", admin(), rid, null);
    }

    private BrokerClient.Response replace(String id, String body) {
        String etag = bff.send("GET", "/v1/admin/systems/" + id, admin(), null, null).header("ETag");
        return bff.send("PUT", "/v1/admin/systems/" + id, admin(), TestTokens.newRequestId(), body, Map.of("If-Match", etag));
    }

    private String userSecretBody() {
        return "{\"baseUrl\":\"" + env.upstreamUrl() + "\",\"adapter\":\"generic-rest\",\"supportedTypes\":[\"user-secret\"],"
                + "\"defaultType\":\"user-secret\",\"secretScheme\":\"Bearer\"}";
    }

    private static List<String> reasons(List<tools.jackson.databind.JsonNode> events) {
        return events.stream().map(event -> event.path("reason").stringValue() + ":" + event.path("outcome").stringValue()).toList();
    }

    // The write of a key is bound to the row it was validated against ------------------------------------

    @Test
    void aKeyWrittenWhileTheIdIsDeletedAndCreatedAgainIsRemoved(CapturedOutput output) {
        String id = createSystem();
        String rid = TestTokens.newRequestId();
        doAnswer(invocation -> {
            Object written = invocation.callRealMethod();
            assertThat(repository.delete(id)).isTrue();
            assertThat(create(id, TestTokens.newRequestId()).status()).isEqualTo(200);
            return written;
        }).when(keys).write(eq(id), any());

        BrokerClient.Response put = bff.send("PUT", "/v1/admin/systems/" + id + "/service-account-key", admin(), rid,
                "{\"value\":\"" + KEY + "\"}");

        assertThat(put.status()).as("another incarnation of the id").isEqualTo(404);
        assertThat(keyEntryStatus(id)).isEqualTo(404);
        assertThat(reasons(AuditLines.of(output, rid))).contains("service_account_key_set:ok", "service_account_key_deleted:ok", "not_found:denied");
        reset(keys);
        assertThat(bff.send("GET", "/v1/admin/systems/" + id + "/service-account-key", admin(), null, null).json().path("set").booleanValue()).isFalse();
    }

    @Test
    void aKeyWrittenWhileTheSystemDropsServiceAccountIsRemovedAnd422(CapturedOutput output) {
        String id = createSystem();
        String rid = TestTokens.newRequestId();
        doAnswer(invocation -> {
            Object written = invocation.callRealMethod();
            assertThat(replace(id, userSecretBody()).status()).isEqualTo(200);
            return written;
        }).when(keys).write(eq(id), any());

        BrokerClient.Response put = bff.send("PUT", "/v1/admin/systems/" + id + "/service-account-key", admin(), rid,
                "{\"value\":\"" + KEY + "\"}");

        assertThat(put.status()).isEqualTo(422);
        assertThat(put.json().path("reason").stringValue()).isEqualTo("system_not_service_account");
        assertThat(keyEntryStatus(id)).isEqualTo(404);
        assertThat(put.body()).doesNotContain(KEY);
        assertThat(reasons(AuditLines.of(output, rid))).contains("service_account_key_set:ok", "service_account_key_deleted:ok",
                "system_not_service_account:denied");
    }

    @Test
    void aKeyWrittenWhileTheSchemeChangesToBasicMustFitItOrIsRemoved() {
        String id = createSystem();
        doAnswer(invocation -> {
            Object written = invocation.callRealMethod();
            assertThat(replace(id, BODY_TEMPLATE.formatted(env.upstreamUrl()).replace("\"Bearer\"", "\"Basic\"")).status()).isEqualTo(200);
            return written;
        }).when(keys).write(eq(id), any());

        BrokerClient.Response put = bff.send("PUT", "/v1/admin/systems/" + id + "/service-account-key", admin(), TestTokens.newRequestId(),
                "{\"value\":\"" + KEY + "\"}");

        assertThat(put.status()).isEqualTo(422);
        assertThat(put.json().path("reason").stringValue()).isEqualTo("value_not_basic_credential");
        assertThat(keyEntryStatus(id)).isEqualTo(404);
    }

    @Test
    void theLosingOfTwoCreatesNeverTouchesTheKeyOfTheWinner() {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);

        assertThat(create(id, TestTokens.newRequestId()).status()).isEqualTo(412);

        assertThat(keyEntryStatus(id)).as("the key of the existing system is still there").isEqualTo(200);
    }

    // Every live key is audited ------------------------------------------------------------------------------

    @Test
    void aFailureAfterTheWriteLeavesTheKeyAuditedAsSet(CapturedOutput output) {
        String id = createSystem();
        AtomicReference<Integer> calls = new AtomicReference<>(0);
        doAnswer(invocation -> {
            if (calls.updateAndGet(n -> n + 1) > 1) {
                throw new org.springframework.dao.DataAccessResourceFailureException("test: database gone");
            }
            return invocation.callRealMethod();
        }).when(repository).findIncarnation(eq(id));
        String rid = TestTokens.newRequestId();

        BrokerClient.Response put = bff.send("PUT", "/v1/admin/systems/" + id + "/service-account-key", admin(), rid,
                "{\"value\":\"" + KEY + "\"}");

        assertThat(put.status()).isEqualTo(503);
        assertThat(keyEntryStatus(id)).as("the key is live").isEqualTo(200);
        assertThat(AuditLines.of(output, rid)).anySatisfy(event -> {
            assertThat(event.path("reason").stringValue()).isEqualTo("service_account_key_set");
            assertThat(event.path("kvVersion").intValue()).isEqualTo(1);
        });
        assertThat(output.getAll()).doesNotContain(KEY);
    }

    // Older versions ---------------------------------------------------------------------------------------

    @Test
    void aReplaceDestroysThePreviousVersion() {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);
        assertThat(putKey(id).json().path("kvVersion").intValue()).isEqualTo(2);

        assertThat(env.bao("GET", "secret/data/mcp/service-accounts/" + id + "?version=1", null).statusCode()).isEqualTo(404);
        assertThat(env.bao("GET", "secret/data/mcp/service-accounts/" + id + "?version=2", null).statusCode()).isEqualTo(200);
    }

    @Test
    void aFailedDestroyIsAuditedAndDoesNotFailTheWrite(CapturedOutput output) {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);
        doThrow(new SecretStoreUnavailableException("secret store unreachable: test")).when(keys).destroy(eq(id), org.mockito.ArgumentMatchers.anyInt());
        String rid = TestTokens.newRequestId();

        BrokerClient.Response put = bff.send("PUT", "/v1/admin/systems/" + id + "/service-account-key", admin(), rid,
                "{\"value\":\"" + KEY + "\"}");

        assertThat(put.status()).isEqualTo(200);
        assertThat(reasons(AuditLines.of(output, rid))).containsExactly("service_account_key_set:ok", "service_account_key_destroy_failed:error");
        assertThat(output.getAll()).doesNotContain(KEY);
    }

    // Orphans and unconditional removal ----------------------------------------------------------------------

    @Test
    void anOrphanWhoseCurrentVersionWasSoftDeletedIsStillCleanedUp() {
        String id = newId();
        leaveOrphan(id);
        assertThat(env.bao("DELETE", "secret/data/mcp/service-accounts/" + id, null).statusCode()).isEqualTo(204);

        assertThat(deleteKey(id, TestTokens.newRequestId()).status()).isEqualTo(204);

        assertThat(keyEntryStatus(id)).isEqualTo(404);
    }

    @Test
    void removingASystemDropsEveryVersionEvenWhenTheCurrentOneIsNotReadable() {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);
        assertThat(env.bao("DELETE", "secret/data/mcp/service-accounts/" + id, null).statusCode()).isEqualTo(204);

        assertThat(deleteSystem(id, null).status()).isEqualTo(204);

        assertThat(keyEntryStatus(id)).isEqualTo(404);
    }

    // A system that stops being a service-account system ------------------------------------------------------

    @Test
    void droppingServiceAccountRemovesTheKey(CapturedOutput output) {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);
        String etag = bff.send("GET", "/v1/admin/systems/" + id, admin(), null, null).header("ETag");
        String rid = TestTokens.newRequestId();

        BrokerClient.Response updated = bff.send("PUT", "/v1/admin/systems/" + id, admin(), rid, userSecretBody(), Map.of("If-Match", etag));

        assertThat(updated.status()).isEqualTo(200);
        assertThat(updated.json().has("serviceAccountKey")).isFalse();
        assertThat(keyEntryStatus(id)).isEqualTo(404);
        assertThat(AuditLines.of(output, rid)).filteredOn(event -> "service_account_key_deleted".equals(event.path("reason").stringValue()))
                .singleElement().satisfies(event -> assertThat(event.path("kvVersion").intValue()).isEqualTo(1));
    }

    @Test
    void anUpdateThatKeepsServiceAccountLeavesTheKeyAlone() {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);

        assertThat(replace(id, BODY_TEMPLATE.formatted(env.upstreamUrl())).status()).isEqualTo(200);

        assertThat(keyEntryStatus(id)).isEqualTo(200);
    }

    @Test
    void aFailedKeyRemovalAfterDroppingServiceAccountIsAuditedAndTheUpdateStays(CapturedOutput output) {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);
        String etag = bff.send("GET", "/v1/admin/systems/" + id, admin(), null, null).header("ETag");
        doThrow(new SecretStoreUnavailableException("secret store unreachable: test")).when(keys).remove(eq(id));
        String rid = TestTokens.newRequestId();

        BrokerClient.Response updated = bff.send("PUT", "/v1/admin/systems/" + id, admin(), rid, userSecretBody(), Map.of("If-Match", etag));

        assertThat(updated.status()).isEqualTo(503);
        assertThat(reasons(AuditLines.of(output, rid))).containsExactly("system_updated:ok", "secret_store_unavailable:error");
        assertThat(repository.find(id).orElseThrow().supportedTypes()).extracting(Enum::name).containsExactly("USER_SECRET");
        reset(keys);
        assertThat(keyEntryStatus(id)).as("still there, and visible to the operator").isEqualTo(200);
        assertThat(deleteKey(id, TestTokens.newRequestId()).status()).as("which can remove it").isEqualTo(204);
        assertThat(keyEntryStatus(id)).isEqualTo(404);
        assertThat(output.getAll()).doesNotContain(KEY);
    }

    private String keyStatusPath(String id) {
        return "/v1/admin/systems/" + id + "/service-account-key";
    }

    @Test
    void aLeftoverKeyIsVisibleOnlyThroughTheKeyEndpointAndNotInTheViewOfASystemWithoutServiceAccount() {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);
        doThrow(new SecretStoreUnavailableException("secret store unreachable: test")).when(keys).remove(eq(id));
        assertThat(replace(id, userSecretBody()).status()).isEqualTo(503);
        reset(keys);

        assertThat(bff.send("GET", "/v1/admin/systems/" + id, admin(), null, null).json().has("serviceAccountKey")).isFalse();
        assertThat(bff.send("GET", keyStatusPath(id), admin(), null, null).json().path("set").booleanValue()).isTrue();
    }

    @Test
    void addingServiceAccountAgainNeverBringsAnOldKeyBack(CapturedOutput output) {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);
        doThrow(new SecretStoreUnavailableException("secret store unreachable: test")).when(keys).remove(eq(id));
        assertThat(replace(id, userSecretBody()).status()).as("the key stays behind").isEqualTo(503);
        reset(keys);
        assertThat(keyEntryStatus(id)).isEqualTo(200);
        String etag = bff.send("GET", "/v1/admin/systems/" + id, admin(), null, null).header("ETag");
        String rid = TestTokens.newRequestId();

        BrokerClient.Response readded = bff.send("PUT", "/v1/admin/systems/" + id, admin(), rid, BODY_TEMPLATE.formatted(env.upstreamUrl()),
                Map.of("If-Match", etag));

        assertThat(readded.status()).isEqualTo(200);
        assertThat(readded.json().path("serviceAccountKey").path("state").stringValue()).isEqualTo("missing");
        assertThat(keyEntryStatus(id)).isEqualTo(404);
        assertThat(reasons(AuditLines.of(output, rid))).contains("service_account_key_deleted:ok", "system_updated:ok");
        assertThat(output.getAll()).doesNotContain(KEY);
    }

    @Test
    void aSystemDoesNotTakeServiceAccountOnTopOfAKeyThatCannotBeRemoved(CapturedOutput output) {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);
        doThrow(new SecretStoreUnavailableException("secret store unreachable: test")).when(keys).remove(eq(id));
        assertThat(replace(id, userSecretBody()).status()).isEqualTo(503);
        String etag = bff.send("GET", "/v1/admin/systems/" + id, admin(), null, null).header("ETag");
        String rid = TestTokens.newRequestId();

        BrokerClient.Response readded = bff.send("PUT", "/v1/admin/systems/" + id, admin(), rid, BODY_TEMPLATE.formatted(env.upstreamUrl()),
                Map.of("If-Match", etag));

        assertThat(readded.status()).isEqualTo(503);
        assertThat(repository.find(id).orElseThrow().supportedTypes()).as("not applied").extracting(Enum::name).containsExactly("USER_SECRET");
        assertThat(bff.send("GET", "/v1/admin/systems/" + id, admin(), null, null).header("ETag")).isEqualTo(etag);
        assertThat(reasons(AuditLines.of(output, rid))).containsExactly("secret_store_unavailable:error");
        reset(keys);
        assertThat(keyEntryStatus(id)).isEqualTo(200);
        assertThat(output.getAll()).doesNotContain(KEY);
    }
}
