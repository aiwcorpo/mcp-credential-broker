package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

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

import pl.aiwcorpo.mcp.broker.authenticator.Base32;
import pl.aiwcorpo.mcp.broker.authenticator.Totp;
import pl.aiwcorpo.mcp.broker.credential.OffboardingService;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.GitLabStub;
import pl.aiwcorpo.mcp.broker.support.InvalidationListener;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import tools.jackson.databind.JsonNode;

/**
 * Offboarding (CC-155) over real mTLS: the purge of a user removes connections, every version of their secrets, OAuth
 * flows in progress, the authenticator with its seed and the lock; it is idempotent, audited per item and as a whole,
 * and the cleanup of connections nobody uses goes the same way.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class OffboardingIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final GitLabStub gitlab = env.gitlab;
    private static final String TOOL = "delete_issue";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @LocalServerPort
    int port;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    OffboardingService offboardingService;

    @Autowired
    org.springframework.data.redis.core.StringRedisTemplate redis;

    BrokerClient gateway;
    BrokerClient bff;
    BrokerClient offboarding;
    TestTokens tokens = env.tokens;
    InvalidationListener invalidations;

    @BeforeEach
    void clients() {
        gateway = new BrokerClient(env.pki.clientContext(env.gatewayClient), port);
        bff = new BrokerClient(env.pki.clientContext(env.bffClient), port);
        offboarding = new BrokerClient(env.pki.clientContext(env.offboardingClient), port);
        invalidations = new InvalidationListener(env);
        gitlab.revokeAccepts();
    }

    @AfterEach
    void closeListener() {
        invalidations.close();
    }

    @Test
    void purgeRemovesEverythingTheBrokerKeepsAboutTheUser(CapturedOutput output) {
        String sub = newSub();
        String hash = SecretKey.hashOf(sub);
        assertThat(putSecret(sub, "jira", "alice-pat").status()).isEqualTo(200);
        assertThat(putSecret(sub, "confluence", "alice-pat").status()).isEqualTo(200);
        GitLabStub.Grant grant = gitlab.issueCode("alice", 7200);
        assertThat(complete(sub, start(sub), grant.code()).status()).isEqualTo(200);
        Started pending = start(sub);
        Registered registered = register(sub);
        for (int i = 0; i < 5; i++) {
            verify(sub, wrongCode(registered.seed));
        }
        assertThat(authenticatorStatus(sub).json().path("lockedUntil").isString()).as("the user is locked").isTrue();

        List<String> dataPaths = new ArrayList<>();
        for (String system : List.of("jira", "confluence", "gitlab")) {
            dataPaths.add("secret/data/mcp/connections/" + new SecretKey(sub, system, version(sub, system)).relativePath());
        }
        String stray = "secret/data/mcp/connections/" + hash + "/jira/orphaned-version";
        assertThat(env.bao("POST", stray, "{\"data\":{\"ciphertext\":\"vault:v1:left-by-a-failed-delete\"}}").statusCode()).isEqualTo(200);
        for (String path : dataPaths) {
            assertThat(env.bao("GET", path, null).statusCode()).isEqualTo(200);
        }
        drain();

        String rid = TestTokens.newRequestId();
        BrokerClient.Response purged = offboarding.send("POST", "/v1/admin/users/" + sub + "/purge", null, rid, null);
        assertThat(purged.status()).isEqualTo(204);
        assertThat(purged.header("X-Request-Id")).isEqualTo(rid);

        assertThat(rows(sub)).isZero();
        for (String path : dataPaths) {
            assertThat(env.bao("GET", path, null).statusCode()).isEqualTo(404);
            assertThat(env.bao("GET", path.replace("/data/", "/metadata/"), null).statusCode()).as("all versions: " + path).isEqualTo(404);
        }
        assertThat(env.bao("GET", stray, null).statusCode()).as("a value no row points at").isEqualTo(404);
        assertThat(env.bao("LIST", "secret/metadata/mcp/connections/" + hash + "/", null).statusCode()).isEqualTo(404);

        assertThat(complete(sub, pending, gitlab.issueCode("alice", 7200).code()).status())
                .as("the OAuth flow in progress is gone").isEqualTo(422);
        assertThat(jdbc.sql("select count(*) from authenticator where sub = ?").param(sub).query(Long.class).single()).isZero();
        assertThat(env.bao("GET", "secret/data/mcp/authenticators/" + hash, null).statusCode()).isEqualTo(404);
        BrokerClient.Response status = authenticatorStatus(sub);
        assertThat(status.json().path("state").stringValue()).isEqualTo("none");
        assertThat(status.json().has("lockedUntil")).as("the block is deleted with the user").isFalse();
        assertThat(resolve(sub, "jira").status()).isEqualTo(409);

        assertThat(gitlab.revokeRequests()).extracting(form -> form.get("token"))
                .contains(grant.accessToken(), grant.refreshToken());
        Set<String> announced = new HashSet<>();
        for (JsonNode event = invalidations.next(1500); event != null; event = invalidations.next(300)) {
            assertThat(event.path("sub").stringValue()).isEqualTo(sub);
            announced.add(event.path("system").stringValue());
        }
        assertThat(announced).containsExactlyInAnyOrder("jira", "confluence", "gitlab");

        List<JsonNode> audit = AuditLines.of(output, rid);
        assertThat(audit).filteredOn(e -> "connection_change".equals(e.path("event").stringValue()))
                .extracting(e -> e.path("server").stringValue()).containsExactlyInAnyOrder("mcp-jira", "mcp-confluence", "mcp-gitlab");
        assertThat(audit).filteredOn(e -> "connection_change".equals(e.path("event").stringValue())).allSatisfy(e -> {
            assertThat(e.path("reason").stringValue()).isEqualTo("user_purged");
            assertThat(e.path("outcome").stringValue()).isEqualTo("ok");
            assertThat(e.path("sub").stringValue()).isEqualTo(sub);
            assertThat(e.path("backendUser").stringValue()).isEqualTo("alice");
        });
        assertThat(audit).filteredOn(e -> "authenticator".equals(e.path("event").stringValue())).singleElement().satisfies(e -> {
            assertThat(e.path("reason").stringValue()).isEqualTo("authenticator_removed");
            assertThat(e.path("outcome").stringValue()).isEqualTo("ok");
        });
        assertThat(audit).filteredOn(e -> "admin_change".equals(e.path("event").stringValue())).singleElement().satisfies(e -> {
            assertThat(e.path("reason").stringValue()).isEqualTo("user_purged");
            assertThat(e.path("outcome").stringValue()).isEqualTo("ok");
            assertThat(e.path("sub").stringValue()).isEqualTo(sub);
        });
        assertThat(audit).hasSize(5);
        assertThat(output.getAll()).doesNotContain(grant.accessToken()).doesNotContain(grant.refreshToken())
                .doesNotContain(Base32.encode(registered.seed));
    }

    @Test
    void purgeIsIdempotentAndLeavesATraceEvenWhenThereWasNothingToRemove(CapturedOutput output) {
        String sub = newSub();
        assertThat(putSecret(sub, "jira", "alice-pat").status()).isEqualTo(200);
        assertThat(offboarding.send("POST", "/v1/admin/users/" + sub + "/purge", null, null, null).status()).isEqualTo(204);

        for (String user : List.of(sub, newSub())) {
            String rid = TestTokens.newRequestId();
            assertThat(offboarding.send("POST", "/v1/admin/users/" + user + "/purge", null, rid, null).status()).isEqualTo(204);
            assertThat(AuditLines.of(output, rid)).singleElement().satisfies(e -> {
                assertThat(e.path("event").stringValue()).isEqualTo("admin_change");
                assertThat(e.path("reason").stringValue()).isEqualTo("user_purged");
                assertThat(e.path("outcome").stringValue()).isEqualTo("ok");
                assertThat(e.path("sub").stringValue()).isEqualTo(user);
            });
        }
    }

    @Test
    void onlyTheOffboardingChannelMayPurge(CapturedOutput output) {
        String sub = newSub();
        assertThat(putSecret(sub, "jira", "alice-pat").status()).isEqualTo(200);
        String rid = TestTokens.newRequestId();
        assertThat(bff.send("POST", "/v1/admin/users/" + sub + "/purge", tokens.bffUser(sub, "alice"), rid, null).status())
                .isEqualTo(403);
        assertThat(gateway.send("POST", "/v1/admin/users/" + sub + "/purge", tokens.gatewayUser(sub, "alice", rid), rid, null).status())
                .isEqualTo(403);
        assertThat(offboarding.send("GET", "/v1/admin/users/" + sub + "/purge", null, null, null).status()).isEqualTo(404);
        assertThat(rows(sub)).as("nothing was purged").isEqualTo(1);
        String invalid = TestTokens.newRequestId();
        assertThat(offboarding.send("POST", "/v1/admin/users/" + "x".repeat(256) + "/purge", null, invalid, null).status()).isEqualTo(204);
        assertThat(AuditLines.of(output, invalid)).singleElement().satisfies(e -> {
            assertThat(e.path("event").stringValue()).isEqualTo("admin_change");
            assertThat(e.path("outcome").stringValue()).isEqualTo("ok");
            assertThat(e.has("sub")).isFalse();
        });
    }

    @Test
    void aProviderThatCannotRevokeIsAuditedAndTheConnectionIsRemovedAnyway(CapturedOutput output) {
        String sub = newSub();
        GitLabStub.Grant grant = gitlab.issueCode("alice", 7200);
        assertThat(complete(sub, start(sub), grant.code()).status()).isEqualTo(200);
        gitlab.revokeAnswers(500);

        String rid = TestTokens.newRequestId();
        assertThat(offboarding.send("POST", "/v1/admin/users/" + sub + "/purge", null, rid, null).status()).isEqualTo(204);

        assertThat(rows(sub)).isZero();
        List<JsonNode> audit = AuditLines.of(output, rid);
        assertThat(audit).filteredOn(e -> "provider_revoke_failed".equals(e.path("reason").stringValue())).singleElement()
                .satisfies(e -> {
                    assertThat(e.path("event").stringValue()).isEqualTo("connection_change");
                    assertThat(e.path("outcome").stringValue()).isEqualTo("error");
                    assertThat(e.path("server").stringValue()).isEqualTo("mcp-gitlab");
                    assertThat(e.path("credentialType").stringValue()).isEqualTo("user-oauth");
                });
        assertThat(audit).filteredOn(e -> "user_purged".equals(e.path("reason").stringValue()) && "ok".equals(e.path("outcome").stringValue()))
                .hasSize(2);

        String sub2 = newSub();
        assertThat(complete(sub2, start(sub2), gitlab.issueCode("alice", 7200).code()).status()).isEqualTo(200);
        String disconnect = TestTokens.newRequestId();
        assertThat(bff.send("DELETE", "/v1/connections/gitlab", tokens.bffUser(sub2, "alice"), disconnect, null).status()).isEqualTo(204);
        assertThat(AuditLines.of(output, disconnect)).extracting(e -> e.path("reason").stringValue())
                .containsExactlyInAnyOrder("provider_revoke_failed", "disconnected");
        gitlab.revokeAccepts();
    }

    @Test
    void aSecretStoreOutageFailsThePurgeButDoesNotStopTheOtherStepsAndARepeatFinishesIt(CapturedOutput output) {
        String sub = newSub();
        assertThat(putSecret(sub, "jira", "alice-pat").status()).isEqualTo(200);
        Registered registered = register(sub);
        String path = "secret/data/mcp/connections/" + new SecretKey(sub, "jira", version(sub, "jira")).relativePath();

        String rid = TestTokens.newRequestId();
        BrokerClient.Response failed;
        env.openbao.getDockerClient().pauseContainerCmd(env.openbao.getContainerId()).exec();
        try {
            failed = offboarding.send("POST", "/v1/admin/users/" + sub + "/purge", null, rid, null);
        } finally {
            env.openbao.getDockerClient().unpauseContainerCmd(env.openbao.getContainerId()).exec();
        }
        assertThat(failed.status()).isEqualTo(503);
        assertThat(rows(sub)).as("a connection whose secret could not be deleted stays, so the repeat can finish it").isEqualTo(1);
        assertThat(jdbc.sql("select count(*) from authenticator where sub = ?").param(sub).query(Long.class).single())
                .as("the authenticator step ran anyway").isZero();
        assertThat(AuditLines.of(output, rid)).filteredOn(e -> "admin_change".equals(e.path("event").stringValue())).singleElement()
                .satisfies(e -> assertThat(e.path("outcome").stringValue()).isEqualTo("error"));

        assertThat(offboarding.send("POST", "/v1/admin/users/" + sub + "/purge", null, null, null).status()).isEqualTo(204);
        assertThat(rows(sub)).isZero();
        assertThat(env.bao("GET", path.replace("/data/", "/metadata/"), null).statusCode()).isEqualTo(404);
        assertThat(env.bao("GET", "secret/data/mcp/authenticators/" + SecretKey.hashOf(sub), null).statusCode()).isEqualTo(404);
        assertThat(registered.seed).isNotEmpty();
    }

    @Test
    void aDatabaseOutageDoesNotKeepThePurgeFromDeletingSecrets() {
        String sub = newSub();
        assertThat(putSecret(sub, "jira", "alice-pat").status()).isEqualTo(200);
        String path = "secret/data/mcp/connections/" + new SecretKey(sub, "jira", version(sub, "jira")).relativePath();
        BrokerClient.Response failed;
        env.postgres.getDockerClient().pauseContainerCmd(env.postgres.getContainerId()).exec();
        try {
            failed = offboarding.send("POST", "/v1/admin/users/" + sub + "/purge", null, null, null);
        } finally {
            env.postgres.getDockerClient().unpauseContainerCmd(env.postgres.getContainerId()).exec();
        }
        assertThat(failed.status()).isEqualTo(503);
        assertThat(env.bao("GET", path.replace("/data/", "/metadata/"), null).statusCode())
                .as("the secret store step ran although the database did not answer").isEqualTo(404);
        assertThat(offboarding.send("POST", "/v1/admin/users/" + sub + "/purge", null, null, null).status()).isEqualTo(204);
        assertThat(rows(sub)).isZero();
    }

    @Test
    void aConnectionThatCannotBeRemovedDoesNotStopTheCleanupOfTheOthers() {
        String stuck = newSub();
        String stale = newSub();
        assertThat(complete(stuck, start(stuck), gitlab.issueCode("alice", 7200).code()).status()).isEqualTo(200);
        assertThat(putSecret(stale, "jira", "alice-pat").status()).isEqualTo(200);
        age(stuck, Instant.now().minus(300, ChronoUnit.DAYS), null);
        age(stale, Instant.now().minus(200, ChronoUnit.DAYS), null);
        String lock = "broker:oauth:refresh:" + SecretKey.hashOf(stuck) + ":gitlab";
        redis.opsForValue().set(lock, "held-by-the-test", java.time.Duration.ofSeconds(30));
        try {
            assertThat(offboardingService.removeUnused()).isEqualTo(1);
        } finally {
            redis.delete(lock);
        }
        assertThat(rows(stale)).isZero();
        assertThat(rows(stuck)).isEqualTo(1);
        assertThat(offboardingService.removeUnused()).as("the next run takes it").isEqualTo(1);
    }

    @Test
    void connectionsNobodyUsesAreRemovedAfterTheRetention(CapturedOutput output) {
        String stale = newSub();
        String neverUsed = newSub();
        String usedRecently = newSub();
        String fresh = newSub();
        for (String sub : List.of(stale, neverUsed, usedRecently, fresh)) {
            assertThat(putSecret(sub, "jira", "alice-pat").status()).isEqualTo(200);
        }
        Instant old = Instant.now().minus(200, ChronoUnit.DAYS);
        age(stale, old, Instant.now().minus(181, ChronoUnit.DAYS));
        age(neverUsed, Instant.now().minus(181, ChronoUnit.DAYS), null);
        age(usedRecently, old, Instant.now().minus(10, ChronoUnit.DAYS));
        String staleData = "secret/data/mcp/connections/" + new SecretKey(stale, "jira", version(stale, "jira")).relativePath();
        drain();

        assertThat(offboardingService.removeUnused()).isEqualTo(2);

        assertThat(rows(stale)).isZero();
        assertThat(rows(neverUsed)).isZero();
        assertThat(rows(usedRecently)).isEqualTo(1);
        assertThat(rows(fresh)).isEqualTo(1);
        assertThat(env.bao("GET", staleData.replace("/data/", "/metadata/"), null).statusCode()).isEqualTo(404);
        assertThat(resolve(stale, "jira").status()).isEqualTo(409);
        assertThat(resolve(usedRecently, "jira").status()).isEqualTo(200);

        Set<String> announced = new HashSet<>();
        for (JsonNode event = invalidations.next(1500); event != null; event = invalidations.next(300)) {
            announced.add(event.path("sub").stringValue());
        }
        assertThat(announced).containsExactlyInAnyOrder(stale, neverUsed);
        List<JsonNode> cleanups = output.getAll().lines()
                .filter(line -> line.startsWith("{") && line.contains("\"reason\":\"unused_cleanup\""))
                .map(line -> pl.aiwcorpo.mcp.broker.support.Contracts.JSON.readTree(line)).toList();
        assertThat(cleanups).extracting(e -> e.path("sub").stringValue()).containsExactlyInAnyOrder(stale, neverUsed);
        for (JsonNode event : cleanups) {
            assertThat(AuditLines.of(output, event.path("requestId").stringValue())).singleElement().satisfies(e -> {
                assertThat(e.path("event").stringValue()).isEqualTo("connection_change");
                assertThat(e.path("outcome").stringValue()).isEqualTo("ok");
                assertThat(e.path("credentialType").stringValue()).isEqualTo("user-secret");
            });
        }
        assertThat(offboardingService.removeUnused()).as("nothing left to remove").isZero();
    }

    // Helpers --------------------------------------------------------------------------------------------

    private void age(String sub, Instant connectedAt, Instant lastUsedAt) {
        jdbc.sql("update connection set connected_at = :c, last_used_at = :u where sub = :sub")
                .param("c", Timestamp.from(connectedAt))
                .param("u", lastUsedAt == null ? null : Timestamp.from(lastUsedAt))
                .param("sub", sub).update();
    }

    private void drain() {
        while (invalidations.next(200) != null) {
            // events of the setup are not the ones under test
        }
    }

    private String version(String sub, String system) {
        return jdbc.sql("select secret_version from connection where sub = ? and system = ?").param(sub).param(system)
                .query(String.class).single();
    }

    private long rows(String sub) {
        return jdbc.sql("select count(*) from connection where sub = ?").param(sub).query(Long.class).single();
    }

    private BrokerClient.Response putSecret(String sub, String system, String secret) {
        return bff.send("PUT", "/v1/connections/" + system + "/secret", tokens.bffUser(sub, "alice"), null,
                "{\"secret\":\"" + secret + "\"}");
    }

    private BrokerClient.Response resolve(String sub, String system) {
        String rid = TestTokens.newRequestId();
        return gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", rid), rid,
                "{\"system\":\"" + system + "\"}");
    }

    record Started(String flowId, String state) {
    }

    private Started start(String sub) {
        BrokerClient.Response response = bff.send("POST", "/v1/connections/gitlab/oauth/start", tokens.bffUser(sub, "alice"), null,
                "{\"returnPath\":\"/catalog\"}");
        assertThat(response.status()).isEqualTo(200);
        Map<String, String> query = new LinkedHashMap<>();
        for (String pair : URI.create(response.json().path("authorizeUrl").stringValue()).getRawQuery().split("&")) {
            int eq = pair.indexOf('=');
            query.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return new Started(response.json().path("flowId").stringValue(), query.get("state"));
    }

    private BrokerClient.Response complete(String sub, Started started, String code) {
        return bff.send("POST", "/v1/connections/gitlab/oauth/complete", tokens.bffUser(sub, "alice"), null,
                "{\"flowId\":\"" + started.flowId() + "\",\"code\":\"" + code + "\",\"state\":\"" + started.state() + "\"}");
    }

    record Registered(byte[] seed) {
    }

    private Registered register(String sub) {
        String bffToken = tokens.bffUser(sub, "alice");
        BrokerClient.Response started = bff.send("POST", "/v1/authenticator/enrollment", bffToken, null, null);
        assertThat(started.status()).isEqualTo(201);
        byte[] seed = Base32.decode(started.json().path("secret").stringValue());
        assertThat(bff.send("POST", "/v1/authenticator/enrollment/confirm", bffToken, null,
                "{\"enrollmentId\":\"" + started.json().path("enrollmentId").stringValue() + "\",\"code\":\""
                        + Totp.code(seed, Totp.stepOf(Instant.now())) + "\"}").status()).isEqualTo(200);
        return new Registered(seed);
    }

    private BrokerClient.Response verify(String sub, String code) {
        return authenticator("POST", "/v1/authenticator/verify", sub, "{\"code\":\"" + code + "\"}");
    }

    private BrokerClient.Response authenticatorStatus(String sub) {
        return authenticator("GET", "/v1/authenticator", sub, null);
    }

    private BrokerClient.Response authenticator(String method, String path, String sub, String body) {
        String rid = TestTokens.newRequestId();
        return gateway.send(method, path, tokens.gatewayUser(sub, "alice", rid, TOOL), rid, body);
    }

    private static String wrongCode(byte[] seed) {
        long step = Totp.stepOf(Instant.now());
        List<String> valid = new ArrayList<>();
        for (long offset = -2; offset <= 2; offset++) {
            valid.add(Totp.code(seed, step + offset));
        }
        for (int candidate = 100000; ; candidate++) {
            if (!valid.contains(String.valueOf(candidate))) {
                return String.valueOf(candidate);
            }
        }
    }

    private static String newSub() {
        return "offboarding-it-" + UUID.randomUUID();
    }
}
