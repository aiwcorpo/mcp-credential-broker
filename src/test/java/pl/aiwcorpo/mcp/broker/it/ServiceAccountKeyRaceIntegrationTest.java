package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
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
        reset(keys);
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
        }).when(keys).remove(eq(id), anyBoolean());

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
        }).when(keys).remove(eq(id), anyBoolean());

        assertThat(deleteSystem(id, null).status()).isEqualTo(204);

        assertThat(keyEntryStatus(id)).isEqualTo(404);
    }

    @Test
    void aFailedKeyRemovalAfterTheRowDeleteIsAuditedAndTheSystemStaysDeleted(CapturedOutput output) {
        String id = createSystem();
        assertThat(putKey(id).status()).isEqualTo(200);
        doThrow(new SecretStoreUnavailableException("secret store unreachable: test")).when(keys).remove(eq(id), anyBoolean());
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
}
