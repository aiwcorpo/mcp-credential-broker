package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doThrow;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.credential.OAuthService;
import pl.aiwcorpo.mcp.broker.credential.OffboardingService;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import pl.aiwcorpo.mcp.broker.secret.StoredCredential;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;
import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.GitLabStub;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;

/**
 * A provider that rotates refresh tokens makes a failed save of the new pair expensive: the old token is spent.
 * These tests break the broker's own secret store after the provider has answered.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class OAuthRefreshFailureIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final GitLabStub gitlab = env.gitlab;

    private static final String CLIENT_SECRET_IN_OPENBAO = "client-secret-from-openbao";

    /** This context has no client secret in its configuration: the broker has to take it from OpenBao. */
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
        registry.add("broker.lost-secret-brake.max-marks", () -> "1000");
        registry.add("broker.retention.orphan-secrets-after", () -> "PT1S");
        registry.add("broker.retention.orphan-sweep-delete", () -> "true");
        registry.add("broker.retention.orphan-max-fraction", () -> "1.0");
        registry.add("broker.openbao.oauth-clients-prefix", () -> "mcp/oauth-clients-it");
        var stored = env.bao("POST", "secret/data/mcp/oauth-clients-it/gitlab",
                "{\"data\":{\"client_id\":\"" + TestEnvironment.GITLAB_CLIENT_ID + "\",\"client_secret\":\""
                        + CLIENT_SECRET_IN_OPENBAO + "\"}}");
        assertThat(stored.statusCode()).isLessThan(300);
    }

    @LocalServerPort
    int port;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    OAuthService oauthService;

    @Autowired
    pl.aiwcorpo.mcp.broker.credential.ConnectionRepository connectionRows;

    @MockitoSpyBean
    SecretStore secrets;

    @Autowired
    OffboardingService offboardingService;

    BrokerClient gateway;
    BrokerClient bff;
    BrokerClient offboarding;
    TestTokens tokens = env.tokens;

    @BeforeEach
    void clients() {
        gateway = new BrokerClient(env.pki.clientContext(env.gatewayClient), port);
        bff = new BrokerClient(env.pki.clientContext(env.bffClient), port);
        offboarding = new BrokerClient(env.pki.clientContext(env.offboardingClient), port);
        gitlab.revokeAccepts();
        jdbc.sql("delete from connection where type = 'user-oauth'").update();
    }

    @AfterEach
    void restoreTheStore() {
        Mockito.reset(secrets);
    }

    @Test
    void aTransientStoreFailureAfterTheProviderAnsweredIsRetried() {
        String sub = newSub();
        GitLabStub.Grant first = gitlab.issueCode("alice", 60);
        connect(sub, "alice", first);
        GitLabStub.Grant second = gitlab.rotateOnRefresh(first, 7200, 0);
        doThrow(new SecretStoreUnavailableException("blip")).doCallRealMethod().when(secrets).put(any(), any());

        BrokerClient.Response resolved = resolve(sub, "alice");
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(resolved.json().path("value").stringValue()).isEqualTo(second.accessToken());
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", first.refreshToken())).hasSize(1);
    }

    @Test
    void aStoreThatComesBackWithinTheRetryWindowKeepsTheRotatedGrant() {
        String sub = newSub();
        GitLabStub.Grant first = gitlab.issueCode("alice", 60);
        connect(sub, "alice", first);
        GitLabStub.Grant second = gitlab.rotateOnRefresh(first, 7200, 0);
        doThrow(new SecretStoreUnavailableException("down 1"), new SecretStoreUnavailableException("down 2"),
                new SecretStoreUnavailableException("down 3"), new SecretStoreUnavailableException("down 4"))
                .doCallRealMethod().when(secrets).putRotated(any(), any());

        BrokerClient.Response resolved = resolve(sub, "alice");
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(resolved.json().path("value").stringValue()).isEqualTo(second.accessToken());
        assertThat(state(sub)).isEqualTo("connected");
        Mockito.reset(secrets);
        assertThat(resolve(sub, "alice").json().path("value").stringValue()).isEqualTo(second.accessToken());
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", first.refreshToken())).hasSize(1);
    }

    @Test
    void aLostRefreshTokenIsAnErrorNotARevocationAndTheNewGrantIsNotLeftAlive(CapturedOutput output) {
        String sub = newSub();
        GitLabStub.Grant first = gitlab.issueCode("alice", 60);
        connect(sub, "alice", first);
        GitLabStub.Grant second = gitlab.rotateOnRefresh(first, 7200, 0);
        doThrow(new SecretStoreUnavailableException("down")).when(secrets).put(any(), any());

        assertThat(resolve(sub, "alice").status()).isEqualTo(503);
        Mockito.reset(secrets);

        assertThat(state(sub)).as("the provider withdrew nothing").isEqualTo("error");
        assertThat(gitlab.revokeRequests()).extracting(form -> form.get("token"))
                .contains(second.accessToken(), second.refreshToken());
        assertThat(resolve(sub, "alice").status()).isEqualTo(409);
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", first.refreshToken())).hasSize(1);
        assertThat(output.getAll()).doesNotContain(first.accessToken()).doesNotContain(first.refreshToken())
                .doesNotContain(second.accessToken()).doesNotContain(second.refreshToken());
        assertThat(output.getAll()).contains("\"reason\":\"refresh_token_lost\"");
    }

    @Test
    void aPurgeThatCouldNotRevokeKeepsTheSecretsSoTheRepeatCanRevokeTheGrant() {
        String sub = newSub();
        GitLabStub.Grant grant = gitlab.issueCode("alice", 7200);
        connect(sub, "alice", grant);
        String path = "secret/data/mcp/connections/" + new SecretKey(sub, "gitlab", version(sub)).relativePath();
        doThrow(new SecretStoreUnavailableException("down")).when(secrets).get(any());

        assertThat(offboarding.send("POST", "/v1/admin/users/" + sub + "/purge", null, null, null).status()).isEqualTo(503);
        Mockito.reset(secrets);

        assertThat(state(sub)).as("the row stays").isEqualTo("connected");
        assertThat(env.bao("GET", path, null).statusCode()).as("the value stays, not swept by deleteAllOf").isEqualTo(200);
        assertThat(gitlab.revokeRequests()).extracting(form -> form.get("token")).doesNotContain(grant.accessToken(), grant.refreshToken());

        assertThat(offboarding.send("POST", "/v1/admin/users/" + sub + "/purge", null, null, null).status()).isEqualTo(204);
        assertThat(gitlab.revokeRequests()).extracting(form -> form.get("token")).contains(grant.accessToken(), grant.refreshToken());
        assertThat(env.bao("GET", path, null).statusCode()).isEqualTo(404);
    }

    @Test
    void transitVerdictsOnARealOpenBaoSeparateDamageFromATemporaryProblem() {
        String sub = newSub();
        SecretKey key = SecretKey.newVersion(sub, "jira");
        secrets.put(key, StoredCredential.of(CredentialType.USER_SECRET, SecretValue.of("v")));
        String path = "secret/data/mcp/connections/" + key.relativePath();

        assertThat(env.bao("POST", path, "{\"data\":{\"ciphertext\":\"vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}").statusCode()).isLessThan(300);
        assertThatThrownBy(() -> secrets.get(key)).as("cipher: message authentication failed")
                .isInstanceOf(pl.aiwcorpo.mcp.broker.secret.SecretUnreadableException.class);

        assertThat(env.bao("POST", path, "{\"data\":{\"ciphertext\":\"vault:v9:AAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}").statusCode()).isLessThan(300);
        assertThatThrownBy(() -> secrets.get(key)).as("invalid ciphertext: version is too new")
                .isInstanceOf(pl.aiwcorpo.mcp.broker.secret.StoreRefusedException.class)
                .isNotInstanceOf(pl.aiwcorpo.mcp.broker.secret.SecretUnreadableException.class);

        secrets.delete(key);
    }

    @Test
    void theRenewalSweepSkipsAnUnreadableConnectionAndRenewsTheOnesBehindIt() {
        String damagedSub = newSub();
        String healthySub = newSub();
        GitLabStub.Grant damaged = gitlab.issueCode("alice", 100);
        GitLabStub.Grant healthy = gitlab.issueCode("bob", 200);
        connect(damagedSub, "alice", damaged);
        connect(healthySub, "bob", healthy);
        GitLabStub.Grant renewed = gitlab.rotateOnRefresh(healthy, 7200, 0);
        String path = "secret/data/mcp/connections/" + new SecretKey(damagedSub, "gitlab", version(damagedSub)).relativePath();
        assertThat(env.bao("POST", path, "{\"data\":{\"ciphertext\":\"vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}").statusCode()).isLessThan(300);

        assertThat(oauthService.refreshDue()).isEqualTo(1);

        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", healthy.refreshToken())).hasSize(1);
        assertThat(resolve(healthySub, "bob").json().path("value").stringValue()).isEqualTo(renewed.accessToken());
    }

    @Test
    void replacingAnOAuthConnectionWhoseTokensAreUnreadableIsAuditedAsNotRevoked(CapturedOutput output) {
        String sub = newSub();
        GitLabStub.Grant grant = gitlab.issueCode("alice", 7200);
        connect(sub, "alice", grant);
        String path = "secret/data/mcp/connections/" + new SecretKey(sub, "gitlab", version(sub)).relativePath();
        assertThat(env.bao("POST", path, "{\"data\":{\"ciphertext\":\"vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}").statusCode()).isLessThan(300);
        gitlab.pat("glpat-replacement", "alice");
        String rid = TestTokens.newRequestId();

        BrokerClient.Response put = bff.send("PUT", "/v1/connections/gitlab/secret", tokens.bffUser(sub, "alice"), rid,
                "{\"secret\":\"glpat-replacement\"}");

        assertThat(put.status()).isEqualTo(200);
        assertThat(output.getAll().lines().filter(line -> line.contains(rid) && line.contains("\"reason\":\"provider_revoke_failed\"")).count())
                .isEqualTo(1);
    }

    @Test
    void theSweepRemovesStoredValuesNoRowPointsAtAndKeepsTheReferencedOnes() throws InterruptedException {
        String sub = newSub();
        GitLabStub.Grant grant = gitlab.issueCode("alice", 7200);
        connect(sub, "alice", grant);
        String referenced = "secret/data/mcp/connections/" + new SecretKey(sub, "gitlab", version(sub)).relativePath();
        SecretKey orphan = SecretKey.newVersion(sub, "jira");
        secrets.put(orphan, StoredCredential.of(CredentialType.USER_SECRET, SecretValue.of("orphan-value")));
        String orphanPath = "secret/data/mcp/connections/" + orphan.relativePath();
        SecretKey oauthOrphan = SecretKey.newVersion(sub, "gitlab");
        secrets.put(oauthOrphan, new StoredCredential(CredentialType.USER_OAUTH, SecretValue.of("oauth-orphan"), SecretValue.of("oauth-orphan-refresh")));
        String oauthOrphanPath = "secret/data/mcp/connections/" + oauthOrphan.relativePath();

        Thread.sleep(1_500);
        OffboardingService.OrphanSweep result = offboardingService.sweepOrphanSecrets();

        assertThat(result.refusedBecause()).isNull();
        assertThat(result.deleted()).isPositive();
        assertThat(env.bao("GET", orphanPath, null).statusCode()).isEqualTo(404);
        assertThat(env.bao("GET", oauthOrphanPath, null).statusCode()).as("a grant that cannot be revoked is not deleted").isEqualTo(200);
        assertThat(env.bao("GET", referenced, null).statusCode()).isEqualTo(200);
        env.bao("DELETE", oauthOrphanPath.replace("/data/", "/metadata/"), null);
    }

    @Test
    void anUnreadableStoredEntryDoesNotBlockThePurgeAndIsAuditedAsNotRevoked(CapturedOutput output) {
        String sub = newSub();
        GitLabStub.Grant grant = gitlab.issueCode("alice", 7200);
        connect(sub, "alice", grant);
        String path = "secret/data/mcp/connections/" + new SecretKey(sub, "gitlab", version(sub)).relativePath();
        assertThat(env.bao("POST", path, "{\"data\":{\"ciphertext\":\"vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}").statusCode()).isLessThan(300);
        String rid = TestTokens.newRequestId();

        assertThat(offboarding.send("POST", "/v1/admin/users/" + sub + "/purge", null, rid, null).status()).isEqualTo(204);

        assertThat(jdbc.sql("select count(*) from connection where sub = ?").param(sub).query(Long.class).single()).isZero();
        assertThat(output.getAll().lines().filter(line -> line.contains(rid) && line.contains("\"reason\":\"provider_revoke_failed\"")).count())
                .isEqualTo(1);
        assertThat(env.bao("GET", path, null).statusCode()).isEqualTo(404);
    }

    @Test
    void theSweepStopsAtTheFirstStoreFailureInsteadOfSpendingEveryRefreshToken() {
        GitLabStub.Grant aliceFirst = gitlab.issueCode("alice", 100);
        GitLabStub.Grant bobFirst = gitlab.issueCode("bob", 100);
        connect(newSub(), "alice", aliceFirst);
        connect(newSub(), "bob", bobFirst);
        gitlab.rotateOnRefresh(aliceFirst, 7200, 0);
        gitlab.rotateOnRefresh(bobFirst, 7200, 0);
        doThrow(new SecretStoreUnavailableException("down")).when(secrets).put(any(), any());

        assertThat(oauthService.refreshDue()).isZero();
        Mockito.reset(secrets);

        int spent = gitlab.tokenRequests("refresh_token", "refresh_token", aliceFirst.refreshToken()).size()
                + gitlab.tokenRequests("refresh_token", "refresh_token", bobFirst.refreshToken()).size();
        assertThat(spent).as("the second refresh token is still unspent").isEqualTo(1);
    }

    @Test
    void aSecretGoneFromTheStoreTurnsTheConnectionIntoErrorOnceAndReconnectingRestoresIt(CapturedOutput output) {
        String sub = newSub();
        connect(sub, "alice", gitlab.issueCode("alice", 7200));
        secrets.delete(new SecretKey(sub, "gitlab", version(sub)));

        String rid = TestTokens.newRequestId();
        BrokerClient.Response first = gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", rid), rid,
                "{\"system\":\"gitlab\"}");

        assertThat(first.status()).isEqualTo(409);
        assertThat(state(sub)).isEqualTo("error");
        assertThat(AuditLines.of(output, rid)).filteredOn(e -> "connection_change".equals(e.path("event").stringValue()))
                .singleElement().satisfies(e -> {
                    assertThat(e.path("reason").stringValue()).isEqualTo("secret_missing");
                    assertThat(e.path("outcome").stringValue()).isEqualTo("error");
                    assertThat(e.has("errorCode")).isFalse();
                });
        BrokerClient.Response listed = bff.send("GET", "/v1/connections", tokens.bffUser(sub, "alice"), null, null);
        assertThat(listed.json().get(0).path("status").stringValue()).isEqualTo("error");

        String again = TestTokens.newRequestId();
        assertThat(gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", again), again,
                "{\"system\":\"gitlab\"}").status()).isEqualTo(409);
        assertThat(AuditLines.of(output, again)).extracting(e -> e.path("reason").stringValue()).doesNotContain("secret_missing");

        connect(sub, "alice", gitlab.issueCode("alice", 7200));
        assertThat(state(sub)).isEqualTo("connected");
        assertThat(resolve(sub, "alice").status()).isEqualTo(200);
    }

    @Test
    void rowsWithALostSecretLeaveTheSweepBatchAfterOneVisit() {
        int batch = 100;
        for (int row = 0; row < batch; row++) {
            jdbc.sql("""
                    insert into connection (sub, system, type, state, backend_user, connected_at, updated_at, secret_version, access_expires_at)
                    values (:sub, 'gitlab', 'user-oauth', 'connected', 'ghost', now(), now(), :version, now() - interval '1 hour')
                    """)
                    .param("sub", newSub()).param("version", "lost-" + row).update();
        }
        GitLabStub.Grant healthy = gitlab.issueCode("bob", 200);
        String healthySub = newSub();
        connect(healthySub, "bob", healthy);
        GitLabStub.Grant renewed = gitlab.rotateOnRefresh(healthy, 7200, 0);

        assertThat(oauthService.refreshDue()).as("the whole batch is lost rows").isZero();
        assertThat(jdbc.sql("select count(*) from connection where state = 'error' and backend_user = 'ghost'")
                .query(Long.class).single()).isEqualTo((long) batch);
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", healthy.refreshToken())).isEmpty();

        assertThat(oauthService.refreshDue()).as("the next sweep reaches the connection behind them").isEqualTo(1);
        assertThat(resolve(healthySub, "bob").json().path("value").stringValue()).isEqualTo(renewed.accessToken());
    }

    @Test
    void aStateChangeForASecretVersionTheRowNoLongerPointsAtLeavesTheRowAlone() {
        String sub = newSub();
        connect(sub, "alice", gitlab.issueCode("alice", 7200));
        String current = version(sub);
        java.time.Instant now = java.time.Instant.now();

        assertThat(connectionRows.setStateIfVersion(sub, "gitlab", "replaced-meanwhile", pl.aiwcorpo.mcp.broker.credential.Connection.StoredState.ERROR, now))
                .as("a PUT switched the row to another version after the reader looked").isFalse();
        assertThat(state(sub)).isEqualTo("connected");
        assertThat(connectionRows.setStateIfVersion(sub, "gitlab", current, pl.aiwcorpo.mcp.broker.credential.Connection.StoredState.ERROR, now)).isTrue();
        assertThat(state(sub)).isEqualTo("error");
    }

    @Test
    void aMissingSecretIsMarkedWithoutTouchingTheStore() {
        String sub = newSub();
        connect(sub, "alice", gitlab.issueCode("alice", 7200));
        SecretKey key = new SecretKey(sub, "gitlab", version(sub));
        secrets.delete(key);
        Mockito.clearInvocations(secrets);

        assertThat(resolve(sub, "alice").status()).isEqualTo(409);

        assertThat(state(sub)).isEqualTo("error");
        Mockito.verify(secrets, Mockito.never()).delete(any());
    }

    @Test
    void theClientSecretComesFromOpenBao() {
        GitLabStub.Grant grant = gitlab.issueCode("alice", 7200);
        connect(newSub(), "alice", grant);
        assertThat(gitlab.tokenRequests("authorization_code", "code", grant.code()).getFirst())
                .containsEntry("client_secret", CLIENT_SECRET_IN_OPENBAO);
    }

    private String version(String sub) {
        return jdbc.sql("select secret_version from connection where sub = ? and system = 'gitlab'").param(sub).query(String.class).single();
    }

    private String state(String sub) {
        return jdbc.sql("select state from connection where sub = ? and system = 'gitlab'").param(sub).query(String.class).single();
    }

    private void connect(String sub, String username, GitLabStub.Grant grant) {
        BrokerClient.Response started = bff.send("POST", "/v1/connections/gitlab/oauth/start", tokens.bffUser(sub, username), null,
                "{\"returnPath\":\"/catalog\"}");
        assertThat(started.status()).isEqualTo(200);
        URI url = URI.create(started.json().path("authorizeUrl").stringValue());
        String state = null;
        for (String pair : url.getRawQuery().split("&")) {
            if (pair.startsWith("state=")) {
                state = URLDecoder.decode(pair.substring("state=".length()), StandardCharsets.UTF_8);
            }
        }
        BrokerClient.Response done = bff.send("POST", "/v1/connections/gitlab/oauth/complete", tokens.bffUser(sub, username), null,
                "{\"flowId\":\"" + started.json().path("flowId").stringValue() + "\",\"code\":\"" + grant.code()
                        + "\",\"state\":\"" + state + "\"}");
        assertThat(done.status()).isEqualTo(200);
    }

    private BrokerClient.Response resolve(String sub, String username) {
        String rid = TestTokens.newRequestId();
        return gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, username, rid), rid, "{\"system\":\"gitlab\"}");
    }

    private static String newSub() {
        return UUID.randomUUID().toString();
    }
}
