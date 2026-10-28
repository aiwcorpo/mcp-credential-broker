package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;
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
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import pl.aiwcorpo.mcp.broker.credential.OAuthService;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.GitLabStub;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;

/**
 * A provider that rotates refresh tokens makes a failed save of the new pair expensive: the old token is spent.
 * These tests break the broker's own secret store after the provider has answered.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OAuthRefreshFailureIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final GitLabStub gitlab = env.gitlab;

    private static final String CLIENT_SECRET_IN_OPENBAO = "client-secret-from-openbao";

    /** This context has no client secret in its configuration: the broker has to take it from OpenBao. */
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
        registry.add("broker.systems.gitlab.oauth.client-secret", () -> "");
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

    @MockitoSpyBean
    SecretStore secrets;

    BrokerClient gateway;
    BrokerClient bff;
    TestTokens tokens = env.tokens;

    @BeforeEach
    void clients() {
        gateway = new BrokerClient(env.pki.clientContext(env.gatewayClient), port);
        bff = new BrokerClient(env.pki.clientContext(env.bffClient), port);
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
    void aLostRefreshTokenIsAnErrorNotARevocationAndTheNewGrantIsNotLeftAlive() {
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
    void theClientSecretComesFromOpenBao() {
        GitLabStub.Grant grant = gitlab.issueCode("alice", 7200);
        connect(newSub(), "alice", grant);
        assertThat(gitlab.tokenRequests("authorization_code", "code", grant.code()).getFirst())
                .containsEntry("client_secret", CLIENT_SECRET_IN_OPENBAO);
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
