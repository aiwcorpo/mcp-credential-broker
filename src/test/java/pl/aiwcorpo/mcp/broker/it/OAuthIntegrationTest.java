package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import pl.aiwcorpo.mcp.broker.credential.OAuthService;
import pl.aiwcorpo.mcp.broker.oauth.RefreshLock;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.GitLabStub;
import pl.aiwcorpo.mcp.broker.support.InvalidationListener;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import tools.jackson.databind.JsonNode;

/**
 * "Connect via OAuth" for GitLab (M2 of ws-06) over real mTLS against PostgreSQL, Redis (dev ACL) and OpenBao,
 * with GitLab replaced by a WireMock stub: the flow with PKCE and a one-time state bound to the user, identity
 * check after the exchange, token storage, renewal, revocation, and the negative cases of the Definition of Done.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class OAuthIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final GitLabStub gitlab = env.gitlab;
    private static final String CALLBACK = "https://mcp-portal.test/api/v1/oauth/callback";
    /** Values that must reach only the provider, OpenBao (encrypted) and the gateway's resolve response. */
    private static final List<String> SECRETS = new ArrayList<>(List.of(TestEnvironment.GITLAB_CLIENT_SECRET));

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @LocalServerPort
    int port;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    OAuthService oauthService;

    @Autowired
    StringRedisTemplate redis;

    @Autowired
    RefreshLock refreshLock;

    BrokerClient gateway;
    BrokerClient bff;
    TestTokens tokens = env.tokens;

    record Started(String flowId, String state, String challenge, URI authorizeUrl, Map<String, String> query) {
    }

    @BeforeEach
    void clients() {
        gateway = new BrokerClient(env.pki.clientContext(env.gatewayClient), port);
        bff = new BrokerClient(env.pki.clientContext(env.bffClient), port);
        gitlab.revokeAccepts();
    }

    @AfterAll
    static void noResponseOtherThanResolveCarriesAToken() {
        for (BrokerClient.Response response : BrokerClient.recorded()) {
            String path = response.raw().request().uri().getPath();
            if (path.equals("/v1/credentials/resolve") && response.status() == 200) {
                continue;
            }
            String everything = response.body() + response.raw().headers().map();
            for (String secret : SECRETS) {
                assertThat(everything).as(path).doesNotContain(secret);
            }
        }
    }

    @Test
    void connectsGitLabAndHandsTheTokenToTheGateway(CapturedOutput output) {
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 7200);

        String startRid = TestTokens.newRequestId();
        BrokerClient.Response start = bff.send("POST", "/v1/connections/gitlab/oauth/start", tokens.bffUser(sub, "alice"),
                startRid, "{\"returnPath\":\"/catalog\"}");
        assertThat(start.status()).isEqualTo(200);
        assertThat(start.header("Cache-Control")).isEqualTo("no-store");
        assertThat(Contracts.brokerSchemaErrors("OAuthStartResponse", start.json())).isEmpty();
        Started started = parse(start);
        assertThat(started.authorizeUrl().toString()).startsWith("https://gitlab.test/oauth/authorize?");
        assertThat(started.query()).containsEntry("client_id", TestEnvironment.GITLAB_CLIENT_ID)
                .containsEntry("response_type", "code")
                .containsEntry("redirect_uri", CALLBACK)
                .containsEntry("code_challenge_method", "S256")
                .containsEntry("scope", "read_api api");
        assertThat(started.state()).hasSizeGreaterThanOrEqualTo(32);

        String completeRid = TestTokens.newRequestId();
        BrokerClient.Response done = bff.send("POST", "/v1/connections/gitlab/oauth/complete", tokens.bffUser(sub, "alice"),
                completeRid, completeBody(started.flowId(), grant.code(), started.state()));
        assertThat(done.status()).isEqualTo(200);
        assertThat(done.header("Cache-Control")).isEqualTo("no-store");
        assertThat(Contracts.brokerSchemaErrors("OAuthCompleteResponse", done.json())).isEmpty();
        assertThat(done.json().path("status").stringValue()).isEqualTo("connected");
        assertThat(done.json().path("backendUser").stringValue()).isEqualTo("alice");

        Map<String, String> exchange = gitlab.tokenRequests("authorization_code", "code", grant.code()).getFirst();
        assertThat(exchange).containsEntry("redirect_uri", CALLBACK)
                .containsEntry("client_id", TestEnvironment.GITLAB_CLIENT_ID)
                .containsEntry("client_secret", TestEnvironment.GITLAB_CLIENT_SECRET);
        assertThat(s256(exchange.get("code_verifier"))).as("PKCE: the verifier matches the challenge sent to the user")
                .isEqualTo(started.challenge());
        SECRETS.add(exchange.get("code_verifier"));

        var row = jdbc.sql("select type, state, expires_at, access_expires_at from connection where sub = ? and system = 'gitlab'")
                .param(sub).query().singleRow();
        assertThat(row).containsEntry("type", "user-oauth").containsEntry("state", "connected").containsEntry("expires_at", null);
        assertThat(((Timestamp) row.get("access_expires_at")).toInstant()).isCloseTo(Instant.now().plusSeconds(7200),
                within(1, ChronoUnit.MINUTES));
        var stored = env.bao("GET", storedPath(sub), null);
        assertThat(stored.statusCode()).isEqualTo(200);
        assertThat(stored.body()).doesNotContain(grant.accessToken()).doesNotContain(grant.refreshToken());
        assertThat(Contracts.JSON.readTree(stored.body()).path("data").path("data").path("ciphertext").stringValue())
                .startsWith("vault:v1:");

        BrokerClient.Response resolved = resolve(sub, "alice", "gitlab");
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("ResolvedCredential", resolved.json())).isEmpty();
        assertThat(resolved.json().path("scheme").stringValue()).isEqualTo("Bearer");
        assertThat(resolved.json().path("value").stringValue()).isEqualTo(grant.accessToken());
        assertThat(resolved.json().path("type").stringValue()).isEqualTo("user-oauth");
        assertThat(resolved.json().path("cacheTtlSeconds").asInt()).isEqualTo(60);
        assertThat(resolved.json().path("expiresAt").stringValue()).isNotNull();
        assertThat(resolved.header("Cache-Control")).isEqualTo("no-store");

        BrokerClient.Response list = bff.send("GET", "/v1/connections", tokens.bffUser(sub, "alice"), null, null);
        assertThat(list.json()).hasSize(1);
        JsonNode connection = list.json().get(0);
        assertThat(Contracts.brokerSchemaErrors("Connection", connection)).isEmpty();
        assertThat(connection.path("system").stringValue()).isEqualTo("gitlab");
        assertThat(connection.path("type").stringValue()).isEqualTo("user-oauth");
        assertThat(connection.path("status").stringValue()).isEqualTo("connected");
        assertThat(connection.path("backendUser").stringValue()).isEqualTo("alice");
        assertThat(connection.path("expiresAt").isNull()).as("the renewable access token is not a C4 expiry").isTrue();
        assertThat(connection.path("lastUsedAt").stringValue()).isNotNull();

        assertThat(auditEvents(output, startRid)).singleElement().satisfies(e -> {
            assertThat(e.path("event").stringValue()).isEqualTo("connection_change");
            assertThat(e.path("reason").stringValue()).isEqualTo("oauth_started");
            assertThat(e.path("server").stringValue()).isEqualTo("mcp-gitlab");
            assertThat(e.path("credentialType").stringValue()).isEqualTo("user-oauth");
        });
        assertThat(auditEvents(output, completeRid)).singleElement().satisfies(e -> {
            assertThat(e.path("reason").stringValue()).isEqualTo("oauth_connected");
            assertThat(e.path("outcome").stringValue()).isEqualTo("ok");
            assertThat(e.path("sub").stringValue()).isEqualTo(sub);
            assertThat(e.path("backendUser").stringValue()).isEqualTo("alice");
        });
        assertThat(auditEvents(output, startRid)).singleElement()
                .satisfies(e -> assertThat(e.has("backendUser")).isFalse());
        assertNothingSecretLogged(output, started);
    }

    @Test
    void aStateWorksOnce() {
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 7200);
        Started started = start(sub, "alice");
        assertThat(complete(sub, "alice", started, grant.code()).status()).isEqualTo(200);

        BrokerClient.Response again = complete(sub, "alice", started, grant.code());
        assertThat(again.status()).isEqualTo(422);
        assertThat(Contracts.brokerSchemaErrors("OAuthCompleteError", again.json())).isEmpty();
        assertThat(again.json().path("error").stringValue()).isEqualTo("flow_invalid");
        assertThat(gitlab.tokenRequests("authorization_code", "code", grant.code())).hasSize(1);
    }

    @Test
    void anotherUsersFlowIsRefusedWithoutBurningIt() {
        String alice = newSub();
        String bob = newSub();
        GitLabStub.Grant aliceGrant = grant("alice", 7200);
        GitLabStub.Grant bobGrant = grant("bob", 7200);
        Started started = start(alice, "alice");

        BrokerClient.Response stolen = complete(bob, "bob", started, bobGrant.code());
        assertThat(stolen.status()).isEqualTo(422);
        assertThat(stolen.json().path("error").stringValue()).isEqualTo("flow_invalid");
        assertThat(gitlab.tokenRequests("authorization_code", "code", bobGrant.code())).as("bob's code is never exchanged").isEmpty();
        assertThat(rows(bob)).isZero();
        assertThat(rows(alice)).isZero();

        assertThat(complete(alice, "alice", started, aliceGrant.code()).status()).as("the owner can still finish").isEqualTo(200);
        assertThat(rows(bob)).isZero();
    }

    @Test
    void aWrongStateIsRefusedAndTheOwnersFlowSurvivesIt() {
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 7200);
        Started started = start(sub, "alice");

        BrokerClient.Response wrong = bff.send("POST", "/v1/connections/gitlab/oauth/complete", tokens.bffUser(sub, "alice"), null,
                completeBody(started.flowId(), grant.code(), started.state() + "x"));
        assertThat(wrong.status()).isEqualTo(422);
        assertThat(wrong.json().path("error").stringValue()).isEqualTo("flow_invalid");
        assertThat(gitlab.tokenRequests("authorization_code", "code", grant.code())).isEmpty();
        assertThat(rows(sub)).isZero();
        assertThat(complete(sub, "alice", started, grant.code()).status()).as("a forged callback did not burn the flow").isEqualTo(200);
    }

    @Test
    void aFlowOfOneSystemCannotFinishAnother() {
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 7200);
        Started started = start(sub, "alice");
        BrokerClient.Response other = bff.send("POST", "/v1/connections/jira/oauth/complete", tokens.bffUser(sub, "alice"), null,
                completeBody(started.flowId(), grant.code(), started.state()));
        assertThat(other.status()).isEqualTo(400);
        assertThat(complete(sub, "alice", started, grant.code()).status()).isEqualTo(200);
    }

    @Test
    void aNewStartReplacesThePendingFlowOfTheSameUser() {
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 7200);
        Started first = start(sub, "alice");
        Started second = start(sub, "alice");
        assertThat(second.state()).isNotEqualTo(first.state());

        assertThat(complete(sub, "alice", first, grant.code()).status()).as("link from the earlier start").isEqualTo(422);
        assertThat(complete(sub, "alice", second, grant.code()).status()).isEqualTo(200);
    }

    @Test
    void anExpiredFlowIsInvalid() {
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 7200);
        Started started = start(sub, "alice");
        assertThat(redis.getExpire("broker:oauth:flow:" + started.flowId())).isBetween(1L, 600L);
        redis.delete("broker:oauth:flow:" + started.flowId());

        BrokerClient.Response late = complete(sub, "alice", started, grant.code());
        assertThat(late.status()).isEqualTo(422);
        assertThat(late.json().path("error").stringValue()).isEqualTo("flow_invalid");
    }

    @Test
    void anAccountWithAnotherLoginIsConnectedAndShown() {
        String sub = newSub();
        GitLabStub.Grant bobsCode = grant("bob", 7200);
        Started started = start(sub, "alice");

        BrokerClient.Response response = complete(sub, "alice", started, bobsCode.code());
        assertThat(response.status()).as("no comparison with the SSO identity: logins differ between systems").isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("OAuthCompleteResponse", response.json())).isEmpty();
        assertThat(response.json().path("backendUser").stringValue()).isEqualTo("bob");
        assertThat(rows(sub)).isEqualTo(1);
        BrokerClient.Response list = bff.send("GET", "/v1/connections", tokens.bffUser(sub, "alice"), null, null);
        assertThat(list.json().get(0).path("backendUser").stringValue()).isEqualTo("bob");
        assertThat(resolve(sub, "alice", "gitlab").json().path("value").stringValue()).isEqualTo(bobsCode.accessToken());
        assertThat(gitlab.revokeRequests()).extracting(form -> form.get("token")).doesNotContain(bobsCode.accessToken());
    }

    @Test
    void connectingAnotherAccountReplacesTheOldOneAndRevokesItsGrant() {
        String sub = newSub();
        GitLabStub.Grant good = grant("alice", 7200);
        connect(sub, "alice", good);

        GitLabStub.Grant bobs = grant("bob", 7200);
        assertThat(complete(sub, "alice", start(sub, "alice"), bobs.code()).status()).isEqualTo(200);
        assertThat(resolve(sub, "alice", "gitlab").json().path("value").stringValue()).isEqualTo(bobs.accessToken());
        BrokerClient.Response list = bff.send("GET", "/v1/connections", tokens.bffUser(sub, "alice"), null, null);
        assertThat(list.json().get(0).path("backendUser").stringValue()).isEqualTo("bob");
        assertThat(gitlab.revokeRequests()).extracting(form -> form.get("token")).contains(good.accessToken(), good.refreshToken());
    }

    @Test
    void providerFailuresAreRefusedAndNothingIsStored() {
        String sub = newSub();
        Started serverError = start(sub, "alice");
        gitlab.codeAnswers("code-boom", 500, "server_error", 0);
        BrokerClient.Response boom = complete(sub, "alice", serverError, "code-boom");
        assertThat(boom.status()).isEqualTo(503);
        assertThat(boom.json().path("error").stringValue()).isEqualTo("upstream_unavailable");

        Started usedCode = start(sub, "alice");
        gitlab.codeAnswers("code-used", 400, "invalid_grant", 0);
        BrokerClient.Response used = complete(sub, "alice", usedCode, "code-used");
        assertThat(used.status()).isEqualTo(422);
        assertThat(used.json().path("error").stringValue()).isEqualTo("flow_invalid");

        Started misconfigured = start(sub, "alice");
        gitlab.codeAnswers("code-badclient", 401, "invalid_client", 0);
        assertThat(complete(sub, "alice", misconfigured, "code-badclient").status())
                .as("a rejected client is the broker's problem, not the user's").isEqualTo(503);

        Started slow = start(sub, "alice");
        gitlab.codeAnswers("code-slow", 200, "slow", 2500);
        long begun = System.nanoTime();
        BrokerClient.Response timedOut = complete(sub, "alice", slow, "code-slow");
        assertThat(timedOut.status()).isEqualTo(503);
        assertThat((System.nanoTime() - begun) / 1_000_000).as("bounded by the system timeout").isLessThan(2400);

        assertThat(rows(sub)).isZero();
    }

    @Test
    void startRefusesWhatIsNotAPortalFlow() {
        String token = tokens.bffUser(newSub(), "alice");
        assertThat(bff.send("POST", "/v1/connections/gitlab/oauth/start", token, null, "{\"returnPath\":\"//evil.test/x\"}").status())
                .isEqualTo(400);
        assertThat(bff.send("POST", "/v1/connections/gitlab/oauth/start", token, null, "{\"returnPath\":\"https://evil.test/\"}").status())
                .isEqualTo(400);
        assertThat(bff.send("POST", "/v1/connections/gitlab/oauth/start", token, null, "{\"returnPath\":\"/a%2f%2fb\"}").status())
                .isEqualTo(400);
        assertThat(bff.send("POST", "/v1/connections/gitlab/oauth/start", token, null, "{}").status()).isEqualTo(400);
        assertThat(bff.send("POST", "/v1/connections/gitlab/oauth/start", token, null,
                "{\"returnPath\":\"/catalog\",\"sub\":\"someone-else\"}").status()).isEqualTo(400);
        assertThat(bff.send("POST", "/v1/connections/jira/oauth/start", token, null, "{\"returnPath\":\"/catalog\"}").status())
                .as("Jira has no OAuth in this deployment").isEqualTo(400);
        assertThat(bff.send("POST", "/v1/connections/nosuch/oauth/start", token, null, "{\"returnPath\":\"/catalog\"}").status())
                .isEqualTo(400);

        assertThat(gateway.send("POST", "/v1/connections/gitlab/oauth/start", tokens.gatewayUser(newSub(), "alice",
                TestTokens.newRequestId(), null), null, "{\"returnPath\":\"/catalog\"}").status()).as("only the portal BFF").isEqualTo(403);
        assertThat(bff.send("POST", "/v1/connections/gitlab/oauth/start", null, null, "{\"returnPath\":\"/catalog\"}").status())
                .isEqualTo(401);
        assertThat(bff.send("POST", "/v1/connections/gitlab/oauth/complete", null, null,
                completeBody("flow-x", "c", "s")).status()).isEqualTo(401);
        assertThat(gateway.send("POST", "/v1/connections/gitlab/oauth/complete", tokens.gatewayUser(newSub(), "alice",
                TestTokens.newRequestId(), null), null, completeBody("flow-x", "c", "s")).status()).isEqualTo(403);
    }

    @Test
    void completeRefusesMalformedBodies() {
        String token = tokens.bffUser(newSub(), "alice");
        for (String body : List.of("{}", "{\"flowId\":\"f\",\"code\":\"c\"}", "{\"flowId\":\"\",\"code\":\"c\",\"state\":\"s\"}",
                "{\"flowId\":\"f\",\"code\":\"c\",\"state\":\"s\",\"sub\":\"x\"}", "not json")) {
            assertThat(bff.send("POST", "/v1/connections/gitlab/oauth/complete", token, null, body).status()).as(body).isEqualTo(400);
        }
    }

    @Test
    void oauthReplacesAPatAndAnnouncesIt() {
        String sub = newSub();
        gitlab.pat("glpat-alice-1", "alice");
        assertThat(putSecret(sub, "alice", "{\"secret\":\"glpat-alice-1\"}").status()).isEqualTo(200);
        String patPath = storedPath(sub);
        GitLabStub.Grant grant = grant("alice", 7200);
        try (InvalidationListener listener = new InvalidationListener(env)) {
            assertThat(complete(sub, "alice", start(sub, "alice"), grant.code()).status()).isEqualTo(200);
            JsonNode event = listener.next(5000);
            assertThat(event).isNotNull();
            assertThat(Contracts.schemaErrors("schemas/credential-invalidated-event.schema.json", event)).isEmpty();
            assertThat(event.path("sub").stringValue()).isEqualTo(sub);
            assertThat(event.path("system").stringValue()).isEqualTo("gitlab");
        }
        assertThat(env.bao("GET", patPath, null).statusCode()).isEqualTo(404);
        assertThat(resolve(sub, "alice", "gitlab").json().path("type").stringValue()).isEqualTo("user-oauth");
    }

    @Test
    void gitLabPersonalAccessTokenIsStoredWithItsAccount() {
        String sub = newSub();
        gitlab.pat("glpat-alice-2", "Alice");
        gitlab.pat("glpat-bob-2", "bob");
        BrokerClient.Response put = putSecret(sub, "alice", "{\"secret\":\"glpat-alice-2\"}");
        assertThat(put.status()).isEqualTo(200);
        assertThat(put.json().path("backendUser").stringValue()).isEqualTo("Alice");
        assertThat(put.json().path("expiresAt").isNull()).isTrue();
        BrokerClient.Response resolved = resolve(sub, "alice", "gitlab");
        assertThat(resolved.json().path("type").stringValue()).isEqualTo("user-secret");
        assertThat(resolved.json().path("value").stringValue()).isEqualTo("glpat-alice-2");

        BrokerClient.Response other = putSecret(newSub(), "alice", "{\"secret\":\"glpat-bob-2\"}");
        assertThat(other.status()).isEqualTo(200);
        assertThat(other.json().path("backendUser").stringValue()).isEqualTo("bob");
        assertThat(putSecret(newSub(), "alice", "{\"secret\":\"glpat-unknown\"}").json().path("error").stringValue())
                .isEqualTo("secret_invalid");
    }

    @Test
    void anAccessTokenNearExpiryIsRenewedOnResolve(CapturedOutput output) {
        String sub = newSub();
        GitLabStub.Grant first = grant("alice", 60);
        connect(sub, "alice", first);
        String firstPath = storedPath(sub);
        GitLabStub.Grant second = gitlab.rotateOnRefresh(first, 7200, 0);
        SECRETS.addAll(List.of(second.accessToken(), second.refreshToken()));

        try (InvalidationListener listener = new InvalidationListener(env)) {
            String rid = TestTokens.newRequestId();
            BrokerClient.Response resolved = gateway.send("POST", "/v1/credentials/resolve",
                    tokens.gatewayUser(sub, "alice", rid), rid, "{\"system\":\"gitlab\"}");
            assertThat(resolved.status()).isEqualTo(200);
            assertThat(resolved.json().path("value").stringValue()).isEqualTo(second.accessToken());
            assertThat(listener.next(500)).as("renewal keeps the grant, nothing to invalidate").isNull();
            assertThat(auditEvents(output, rid)).extracting(e -> e.path("reason").stringValue())
                    .containsExactlyInAnyOrder("token_refreshed", "resolved");
        }
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", first.refreshToken())).hasSize(1);
        assertThat(storedPath(sub)).isNotEqualTo(firstPath);
        assertThat(env.bao("GET", firstPath, null).statusCode()).isEqualTo(404);

        assertThat(resolve(sub, "alice", "gitlab").json().path("value").stringValue()).isEqualTo(second.accessToken());
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", first.refreshToken())).as("not renewed twice").hasSize(1);

        GitLabStub.Grant third = gitlab.rotateOnRefresh(second, 7200, 0);
        SECRETS.addAll(List.of(third.accessToken(), third.refreshToken()));
        jdbc.sql("update connection set access_expires_at = now() - interval '1 minute' where sub = ?").param(sub).update();
        assertThat(resolve(sub, "alice", "gitlab").json().path("value").stringValue())
                .as("the rotated refresh token was the one stored").isEqualTo(third.accessToken());
        assertNothingSecretLogged(output, null);
    }

    @Test
    void parallelResolvesRenewOnce() throws Exception {
        String sub = newSub();
        GitLabStub.Grant first = grant("alice", 60);
        connect(sub, "alice", first);
        GitLabStub.Grant second = gitlab.rotateOnRefresh(first, 7200, 600);
        SECRETS.addAll(List.of(second.accessToken(), second.refreshToken()));

        ExecutorService pool = Executors.newFixedThreadPool(6);
        try {
            List<Future<BrokerClient.Response>> calls = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                calls.add(pool.submit(() -> resolve(sub, "alice", "gitlab")));
            }
            for (Future<BrokerClient.Response> call : calls) {
                BrokerClient.Response response = call.get();
                assertThat(response.status()).isEqualTo(200);
                assertThat(response.json().path("value").stringValue()).isEqualTo(second.accessToken());
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", first.refreshToken()))
                .as("a rotated refresh token must not be spent twice").hasSize(1);
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", second.refreshToken()))
                .as("the renewed token is not renewed again by the callers that waited for the lock").isEmpty();
    }

    @Test
    void aDisconnectDuringARefreshWaitsForItAndThenWins() throws Exception {
        String sub = newSub();
        GitLabStub.Grant first = grant("alice", 60);
        connect(sub, "alice", first);
        GitLabStub.Grant second = gitlab.rotateOnRefresh(first, 7200, 700);
        SECRETS.addAll(List.of(second.accessToken(), second.refreshToken()));
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<BrokerClient.Response> during = pool.submit(() -> resolve(sub, "alice", "gitlab"));
            Thread.sleep(250);
            assertThat(bff.send("DELETE", "/v1/connections/gitlab", tokens.bffUser(sub, "alice"), null, null).status()).isEqualTo(204);
            assertThat(during.get().status()).isEqualTo(200);
            assertThat(rows(sub)).as("the connection stays gone").isZero();
            assertThat(resolve(sub, "alice", "gitlab").status()).isEqualTo(409);
            assertThat(gitlab.revokeRequests()).extracting(form -> form.get("token"))
                    .as("the tokens the refresh issued are revoked by the disconnect that followed")
                    .contains(second.accessToken(), second.refreshToken());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void aRefreshThatLostItsLockCannotBringADisconnectedConnectionBack() throws Exception {
        String sub = newSub();
        GitLabStub.Grant first = grant("alice", 60);
        connect(sub, "alice", first);
        GitLabStub.Grant second = gitlab.rotateOnRefresh(first, 7200, 700);
        SECRETS.addAll(List.of(second.accessToken(), second.refreshToken()));
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<BrokerClient.Response> during = pool.submit(() -> resolve(sub, "alice", "gitlab"));
            Thread.sleep(250);
            redis.delete(refreshLockKey(sub));
            assertThat(bff.send("DELETE", "/v1/connections/gitlab", tokens.bffUser(sub, "alice"), null, null).status()).isEqualTo(204);

            assertThat(during.get().status()).as("the refresh finds the connection gone").isEqualTo(409);
            assertThat(rows(sub)).isZero();
            assertThat(resolve(sub, "alice", "gitlab").status()).isEqualTo(409);
            assertThat(gitlab.revokeRequests()).extracting(form -> form.get("token"))
                    .as("the new tokens of the lost race are revoked at the provider")
                    .contains(second.accessToken(), second.refreshToken());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void aLockIsReleasedOnlyByItsOwner() {
        String sub = newSub();
        String first = refreshLock.acquire(sub, "gitlab", java.time.Duration.ZERO).orElseThrow();
        assertThat(refreshLock.acquire(sub, "gitlab", java.time.Duration.ZERO)).as("taken").isEmpty();
        redis.delete(refreshLockKey(sub));
        String second = refreshLock.acquire(sub, "gitlab", java.time.Duration.ZERO).orElseThrow();

        refreshLock.release(sub, "gitlab", first);
        assertThat(redis.hasKey(refreshLockKey(sub))).as("the late release of the expired holder leaves the new holder's lock").isTrue();
        refreshLock.release(sub, "gitlab", second);
        assertThat(redis.hasKey(refreshLockKey(sub))).isFalse();
    }

    @Test
    void connectingAgainRevokesTheGrantItReplaces() {
        String sub = newSub();
        GitLabStub.Grant first = grant("alice", 7200);
        connect(sub, "alice", first);
        GitLabStub.Grant second = grant("alice", 7200);
        connect(sub, "alice", second);

        assertThat(gitlab.revokeRequests()).extracting(form -> form.get("token")).contains(first.accessToken(), first.refreshToken())
                .doesNotContain(second.accessToken(), second.refreshToken());
        assertThat(resolve(sub, "alice", "gitlab").json().path("value").stringValue()).isEqualTo(second.accessToken());
    }

    @Test
    void storingAPatOverAnOAuthConnectionRevokesTheGrant() {
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 7200);
        connect(sub, "alice", grant);
        gitlab.pat("glpat-alice-replacement", "alice");
        SECRETS.add("glpat-alice-replacement");

        assertThat(putSecret(sub, "alice", "{\"secret\":\"glpat-alice-replacement\"}").status()).isEqualTo(200);
        assertThat(gitlab.revokeRequests()).extracting(form -> form.get("token")).contains(grant.accessToken(), grant.refreshToken());
    }

    @Test
    void tokensIssuedForACodeAreRevokedWhenTheWhoamiCannotBeDone() {
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 7200);
        gitlab.whoamiFails(grant.accessToken(), 500);
        Started started = start(sub, "alice");

        assertThat(complete(sub, "alice", started, grant.code()).status()).isEqualTo(503);
        assertThat(rows(sub)).isZero();
        assertThat(gitlab.revokeRequests()).extracting(form -> form.get("token")).contains(grant.accessToken(), grant.refreshToken());
    }

    @Test
    void anOversizedProviderAnswerIsRefusedAsUnavailable() {
        String sub = newSub();
        gitlab.oversizedWhoami("glpat-huge");
        BrokerClient.Response response = putSecret(sub, "alice", "{\"secret\":\"glpat-huge\"}");
        assertThat(response.status()).isEqualTo(503);
        assertThat(rows(sub)).isZero();
    }

    @Test
    void aProviderThatTricklesItsAnswerIsCutOffAtTheTimeout() {
        String sub = newSub();
        gitlab.trickledWhoami("glpat-slow");
        long started = System.nanoTime();
        BrokerClient.Response response = putSecret(sub, "alice", "{\"secret\":\"glpat-slow\"}");
        long seconds = java.time.Duration.ofNanos(System.nanoTime() - started).toSeconds();
        assertThat(response.status()).isEqualTo(503);
        assertThat(seconds).as("the system timeout is 1 s, the body would take 8 s").isLessThan(5);
        assertThat(rows(sub)).isZero();
    }

    @Test
    void aRefreshTokenRevokedAtTheProviderMakesTheConnectionRevoked(CapturedOutput output) {
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 60);
        connect(sub, "alice", grant);
        String path = storedPath(sub);
        gitlab.refreshAnswers(grant, 400, "invalid_grant");

        try (InvalidationListener listener = new InvalidationListener(env)) {
            String rid = TestTokens.newRequestId();
            BrokerClient.Response resolved = gateway.send("POST", "/v1/credentials/resolve",
                    tokens.gatewayUser(sub, "alice", rid), rid, "{\"system\":\"gitlab\"}");
            assertThat(resolved.status()).isEqualTo(409);
            assertThat(Contracts.brokerSchemaErrors("CredentialRequired", resolved.json())).isEmpty();
            assertThat(resolved.json().path("connectUrl").stringValue()).isEqualTo("https://mcp-portal.test/connections?system=gitlab");
            JsonNode event = listener.next(5000);
            assertThat(event).isNotNull();
            assertThat(event.path("sub").stringValue()).isEqualTo(sub);
            assertThat(auditEvents(output, rid)).extracting(e -> e.path("reason").stringValue())
                    .contains("oauth_grant_revoked", "credential_required");
        }
        BrokerClient.Response list = bff.send("GET", "/v1/connections", tokens.bffUser(sub, "alice"), null, null);
        assertThat(list.json().get(0).path("status").stringValue()).isEqualTo("revoked");
        assertThat(env.bao("GET", path, null).statusCode()).as("the dead tokens are removed").isEqualTo(404);
        assertThat(resolve(sub, "alice", "gitlab").status()).isEqualTo(409);
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", grant.refreshToken())).hasSize(1);

        GitLabStub.Grant again = grant("alice", 7200);
        connect(sub, "alice", again);
        assertThat(resolve(sub, "alice", "gitlab").json().path("value").stringValue()).as("reconnecting heals it")
                .isEqualTo(again.accessToken());
    }

    @Test
    void aProviderOutageDoesNotBreakATokenThatStillWorks() {
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 100);
        connect(sub, "alice", grant);
        gitlab.refreshAnswers(grant, 503, "temporarily_unavailable");

        BrokerClient.Response stillValid = resolve(sub, "alice", "gitlab");
        assertThat(stillValid.status()).isEqualTo(200);
        assertThat(stillValid.json().path("value").stringValue()).isEqualTo(grant.accessToken());
        assertThat(stillValid.json().path("cacheTtlSeconds").asInt()).isLessThanOrEqualTo(60);

        jdbc.sql("update connection set access_expires_at = now() - interval '1 minute' where sub = ?").param(sub).update();
        BrokerClient.Response expired = resolve(sub, "alice", "gitlab");
        assertThat(expired.status()).isEqualTo(503);
        BrokerClient.Response list = bff.send("GET", "/v1/connections", tokens.bffUser(sub, "alice"), null, null);
        assertThat(list.json().get(0).path("status").stringValue()).as("an outage is not a revocation").isEqualTo("connected");
    }

    @Test
    void theSweepRenewsTokensBeforeAnyoneAsks() {
        jdbc.sql("delete from connection where type = 'user-oauth'").update();
        String sub = newSub();
        GitLabStub.Grant first = grant("alice", 200);
        connect(sub, "alice", first);
        GitLabStub.Grant second = gitlab.rotateOnRefresh(first, 7200, 0);
        SECRETS.addAll(List.of(second.accessToken(), second.refreshToken()));
        assertThat(resolve(sub, "alice", "gitlab").json().path("value").stringValue())
                .as("200 s left is more than the refresh margin").isEqualTo(first.accessToken());
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", first.refreshToken())).isEmpty();

        assertThat(oauthService.refreshDue()).isEqualTo(1);
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", first.refreshToken())).hasSize(1);
        assertThat(oauthService.refreshDue()).isZero();
        assertThat(resolve(sub, "alice", "gitlab").json().path("value").stringValue()).isEqualTo(second.accessToken());
    }

    @Test
    void theSweepMarksARevokedGrantWithoutAResolve() {
        jdbc.sql("delete from connection where type = 'user-oauth'").update();
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 200);
        connect(sub, "alice", grant);
        gitlab.refreshAnswers(grant, 400, "invalid_grant");

        assertThat(oauthService.refreshDue()).isZero();
        BrokerClient.Response list = bff.send("GET", "/v1/connections", tokens.bffUser(sub, "alice"), null, null);
        assertThat(list.json().get(0).path("status").stringValue()).isEqualTo("revoked");
    }

    @Test
    void disconnectingRevokesTheTokensAtTheProvider() {
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 7200);
        connect(sub, "alice", grant);
        String path = storedPath(sub);

        try (InvalidationListener listener = new InvalidationListener(env)) {
            assertThat(bff.send("DELETE", "/v1/connections/gitlab", tokens.bffUser(sub, "alice"), null, null).status()).isEqualTo(204);
            assertThat(listener.next(5000)).isNotNull();
        }
        assertThat(gitlab.revokeRequests()).extracting(form -> form.get("token"))
                .contains(grant.accessToken(), grant.refreshToken());
        assertThat(rows(sub)).isZero();
        assertThat(env.bao("GET", path, null).statusCode()).isEqualTo(404);
        assertThat(resolve(sub, "alice", "gitlab").status()).isEqualTo(409);
    }

    @Test
    void disconnectingWorksWhenTheProviderIsDown() {
        String sub = newSub();
        GitLabStub.Grant grant = grant("alice", 7200);
        connect(sub, "alice", grant);
        gitlab.revokeAnswers(500);
        assertThat(bff.send("DELETE", "/v1/connections/gitlab", tokens.bffUser(sub, "alice"), null, null).status()).isEqualTo(204);
        assertThat(rows(sub)).isZero();
        gitlab.revokeAccepts();
    }

    @Test
    void theCatalogSeesGitLabAsOAuthWithItsScopes() {
        BrokerClient.Response systems = bff.send("GET", "/v1/systems", tokens.bffUser(newSub(), "alice"), null, null);
        assertThat(systems.status()).isEqualTo(200);
        JsonNode gitlabInfo = null;
        for (JsonNode info : systems.json()) {
            assertThat(Contracts.brokerSchemaErrors("SystemInfo", info)).isEmpty();
            if ("gitlab".equals(info.path("system").stringValue())) {
                gitlabInfo = info;
            }
        }
        assertThat(gitlabInfo).isNotNull();
        assertThat(gitlabInfo.path("defaultType").stringValue()).isEqualTo("user-oauth");
        assertThat(gitlabInfo.path("supportedTypes")).extracting(JsonNode::stringValue).containsExactly("user-oauth", "user-secret");
        assertThat(gitlabInfo.path("oauthScopes")).extracting(JsonNode::stringValue).containsExactly("read_api", "api");
        for (JsonNode info : systems.json()) {
            if ("jira".equals(info.path("system").stringValue())) {
                assertThat(info.path("oauthScopes")).as("no scopes configured means an empty list").isEmpty();
            }
        }
    }

    private GitLabStub.Grant grant(String user, int expiresIn) {
        GitLabStub.Grant grant = gitlab.issueCode(user, expiresIn);
        SECRETS.addAll(List.of(grant.accessToken(), grant.refreshToken(), grant.code()));
        return grant;
    }

    private void connect(String sub, String username, GitLabStub.Grant grant) {
        assertThat(complete(sub, username, start(sub, username), grant.code()).status()).isEqualTo(200);
    }

    private Started start(String sub, String username) {
        BrokerClient.Response response = bff.send("POST", "/v1/connections/gitlab/oauth/start", tokens.bffUser(sub, username), null,
                "{\"returnPath\":\"/catalog\"}");
        assertThat(response.status()).isEqualTo(200);
        return parse(response);
    }

    private BrokerClient.Response complete(String sub, String username, Started started, String code) {
        return bff.send("POST", "/v1/connections/gitlab/oauth/complete", tokens.bffUser(sub, username), null,
                completeBody(started.flowId(), code, started.state()));
    }

    private static String completeBody(String flowId, String code, String state) {
        return "{\"flowId\":\"" + flowId + "\",\"code\":\"" + code + "\",\"state\":\"" + state + "\"}";
    }

    private static Started parse(BrokerClient.Response response) {
        URI url = URI.create(response.json().path("authorizeUrl").stringValue());
        Map<String, String> query = new LinkedHashMap<>();
        for (String pair : url.getRawQuery().split("&")) {
            int eq = pair.indexOf('=');
            query.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return new Started(response.json().path("flowId").stringValue(), query.get("state"), query.get("code_challenge"), url, query);
    }

    private BrokerClient.Response putSecret(String sub, String username, String body) {
        return bff.send("PUT", "/v1/connections/gitlab/secret", tokens.bffUser(sub, username), null, body);
    }

    private BrokerClient.Response resolve(String sub, String username, String system) {
        String rid = TestTokens.newRequestId();
        return gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, username, rid), rid,
                "{\"system\":\"" + system + "\"}");
    }

    private String storedPath(String sub) {
        String version = jdbc.sql("select secret_version from connection where sub = ? and system = 'gitlab'").param(sub)
                .query(String.class).single();
        return "secret/data/mcp/connections/" + new SecretKey(sub, "gitlab", version).relativePath();
    }

    private static String refreshLockKey(String sub) {
        return "broker:oauth:refresh:" + new SecretKey(sub, "gitlab", null).subHash() + ":gitlab";
    }

    private long rows(String sub) {
        return jdbc.sql("select count(*) from connection where sub = ?").param(sub).query(Long.class).single();
    }

    private static String s256(String verifier) {
        try {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String newSub() {
        return UUID.randomUUID().toString();
    }

    private static List<JsonNode> auditEvents(CapturedOutput output, String requestId) {
        List<JsonNode> events = output.getAll().lines()
                .filter(line -> line.startsWith("{") && line.contains("\"component\":\"broker\""))
                .map(line -> Contracts.JSON.readTree(line))
                .filter(event -> requestId.equals(event.path("requestId").stringValue()))
                .toList();
        for (JsonNode event : events) {
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).as(event.toString()).isEmpty();
        }
        return events;
    }

    private static void assertNothingSecretLogged(CapturedOutput output, Started started) {
        for (String secret : SECRETS) {
            assertThat(output.getAll()).as("secret in the process output").doesNotContain(secret);
        }
        if (started != null) {
            assertThat(output.getAll()).doesNotContain(started.state()).doesNotContain(started.challenge());
        }
    }
}
