package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import com.github.tomakehurst.wiremock.verification.LoggedRequest;

import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.IdpStub;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import tools.jackson.databind.JsonNode;

/**
 * The token-exchange type (CC-157) for OpenSearch over real mTLS: the subjectToken is verified against the IdP's keys
 * before anything is exchanged, the exchange is RFC 8693 against a stand-in for the IdP, and nothing is stored.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class TokenExchangeIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final IdpStub idp = env.idp;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @LocalServerPort
    int port;

    BrokerClient gateway;
    TestTokens tokens = env.tokens;

    @BeforeEach
    void clients() {
        gateway = new BrokerClient(env.pki.clientContext(env.gatewayClient), port);
    }

    @Test
    void exchangesTheUsersTokenForOpenSearchAndStoresNothing(CapturedOutput output) {
        String sub = UUID.randomUUID().toString();
        String subjectToken = tokens.subjectToken(sub, "alice");
        String issued = "os-token-" + UUID.randomUUID();
        idp.issues(subjectToken, issued, 300);

        String rid = TestTokens.newRequestId();
        BrokerClient.Response resolved = resolve(sub, rid, subjectToken);

        assertThat(resolved.status()).isEqualTo(200);
        JsonNode body = resolved.json();
        assertThat(Contracts.brokerSchemaErrors("ResolvedCredential", body)).isEmpty();
        assertThat(body.path("scheme").stringValue()).isEqualTo("Bearer");
        assertThat(body.path("value").stringValue()).isEqualTo(issued);
        assertThat(body.path("type").stringValue()).isEqualTo("token-exchange");
        assertThat(Instant.parse(body.path("expiresAt").stringValue()))
                .isCloseTo(Instant.now().plusSeconds(300), within(10, ChronoUnit.SECONDS));
        assertThat(body.path("cacheTtlSeconds").asInt()).isBetween(1, 60);
        assertThat(resolved.header("Cache-Control")).isEqualTo("no-store");

        LoggedRequest sent = idp.requests().stream()
                .filter(r -> IdpStub.form(r).get("subject_token").equals(subjectToken)).findFirst().orElseThrow();
        assertThat(IdpStub.form(sent)).containsEntry("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                .containsEntry("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
                .containsEntry("audience", "opensearch").containsEntry("scope", "opensearch-audience")
                .doesNotContainKeys("client_secret", "client_id");
        String basic = Base64.getEncoder().encodeToString((URLEncoder.encode(TestEnvironment.EXCHANGE_CLIENT_ID, StandardCharsets.UTF_8)
                + ":" + URLEncoder.encode(TestEnvironment.EXCHANGE_CLIENT_SECRET, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
        assertThat(sent.getHeader("Authorization")).isEqualTo("Basic " + basic);

        assertThat(env.bao("LIST", "secret/metadata/mcp/connections/" + SecretKey.hashOf(sub) + "/", null).statusCode())
                .as("nothing is stored in OpenBao").isEqualTo(404);
        List<JsonNode> audit = AuditLines.of(output, rid);
        assertThat(audit).singleElement().satisfies(e -> {
            assertThat(e.path("event").stringValue()).isEqualTo("credential_resolve");
            assertThat(e.path("outcome").stringValue()).isEqualTo("ok");
            assertThat(e.path("server").stringValue()).isEqualTo("mcp-opensearch");
            assertThat(e.path("credentialType").stringValue()).isEqualTo("token-exchange");
        });
        assertThat(output.getAll()).doesNotContain(issued).doesNotContain(subjectToken)
                .doesNotContain(TestEnvironment.EXCHANGE_CLIENT_SECRET);
    }

    @Test
    void theCacheNeverOutlivesAShortToken() {
        String sub = UUID.randomUUID().toString();
        String subjectToken = tokens.subjectToken(sub, "alice");
        idp.issues(subjectToken, "os-short-" + UUID.randomUUID(), 20);
        BrokerClient.Response resolved = resolve(sub, TestTokens.newRequestId(), subjectToken);
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(resolved.json().path("cacheTtlSeconds").asInt()).isBetween(1, 20);
        assertThat(Instant.parse(resolved.json().path("expiresAt").stringValue()))
                .isBeforeOrEqualTo(Instant.now().plusSeconds(21));
    }

    @Test
    void theExpiryComesFromTheTokenWhenTheIdpLeavesOutExpiresIn() {
        String sub = UUID.randomUUID().toString();
        String subjectToken = tokens.subjectToken(sub, "alice");
        String jwt = tokens.idpToken(TestTokens.IDP_ISSUER, sub, "alice", "mcp-credential-broker", "opensearch",
                Instant.now().plusSeconds(120));
        idp.issues(subjectToken, jwt, null);
        BrokerClient.Response resolved = resolve(sub, TestTokens.newRequestId(), subjectToken);
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(Instant.parse(resolved.json().path("expiresAt").stringValue()))
                .isCloseTo(Instant.now().plusSeconds(120), within(5, ChronoUnit.SECONDS));

        String noExpiry = tokens.subjectToken(sub, "alice");
        idp.issues(noExpiry, "opaque-token-without-expiry", null);
        assertThat(resolve(sub, TestTokens.newRequestId(), noExpiry).status())
                .as("a token without any expiry cannot be handed out (expiresAt is never null)").isEqualTo(503);
    }

    @Test
    void aSubjectTokenThatIsNotTheCallersIsRefusedBeforeTheIdpIsAsked(CapturedOutput output) {
        String alice = UUID.randomUUID().toString();
        String mallory = UUID.randomUUID().toString();
        int before = idp.requests().size();

        String otherUser = tokens.subjectToken(mallory, "mallory");
        String wrongAudience = tokens.idpToken(TestTokens.IDP_ISSUER, alice, "alice", "mcp-gateway", "mcp-gateway-admin",
                Instant.now().plusSeconds(300));
        String expired = tokens.idpToken(TestTokens.IDP_ISSUER, alice, "alice", "mcp-gateway", "mcp-credential-broker",
                Instant.now().minusSeconds(120));
        String wrongIssuer = tokens.idpToken("http://evil.test/realms/corp", alice, "alice", "mcp-gateway",
                "mcp-credential-broker", Instant.now().plusSeconds(300));
        String noExpiry = tokens.idpToken(TestTokens.IDP_ISSUER, alice, "alice", "mcp-gateway", "mcp-credential-broker", null);
        String wrongType = tokens.idpToken(TestTokens.IDP_ISSUER, alice, "alice", "mcp-gateway", "mcp-credential-broker",
                Instant.now().plusSeconds(300), new com.nimbusds.jose.JOSEObjectType("logout+jwt"));
        for (String token : List.of(otherUser, wrongAudience, expired, wrongIssuer, "not-a-jwt", forgedSignature(alice), noExpiry, wrongType,
                tokens.unsecuredSubjectToken(alice), tokens.hmacSubjectToken(alice))) {
            idp.issues(token, "must-never-be-issued", 300);
            String rid = TestTokens.newRequestId();
            BrokerClient.Response response = resolve(alice, rid, token);
            assertThat(response.status()).as(token).isEqualTo(400);
            assertThat(response.json().path("error").stringValue()).isEqualTo("invalid_request");
            assertThat(Contracts.brokerSchemaErrors("Error", response.json())).isEmpty();
            assertThat(response.body()).doesNotContain("must-never-be-issued");
            assertThat(AuditLines.of(output, rid)).singleElement().satisfies(e -> {
                assertThat(e.path("reason").stringValue()).isEqualTo("subject_token_invalid");
                assertThat(e.path("outcome").stringValue()).isEqualTo("denied");
                assertThat(e.path("credentialType").stringValue()).isEqualTo("token-exchange");
            });
        }
        assertThat(idp.requests()).as("no exchange was attempted").hasSize(before);
    }

    @Test
    void aMissingSubjectTokenIsABadRequest(CapturedOutput output) {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response response = resolve(UUID.randomUUID().toString(), rid, null);
        assertThat(response.status()).isEqualTo(400);
        assertThat(AuditLines.of(output, rid)).singleElement()
                .satisfies(e -> assertThat(e.path("reason").stringValue()).isEqualTo("invalid_request"));
    }

    @Test
    void whenTheIdpRefusesTheUserGets403ExchangeDenied(CapturedOutput output) {
        for (String error : List.of("access_denied", "invalid_target", "invalid_request")) {
            String sub = UUID.randomUUID().toString();
            String subjectToken = tokens.subjectToken(sub, "alice");
            idp.refuses(subjectToken, error.equals("access_denied") ? 403 : 400, error);
            String rid = TestTokens.newRequestId();
            BrokerClient.Response response = resolve(sub, rid, subjectToken);
            assertThat(response.status()).as(error).isEqualTo(403);
            assertThat(response.body()).isEqualTo("{\"error\":\"exchange_denied\"}");
            assertThat(output.getAll()).contains("IdP refused the token exchange for audience opensearch: " + error);
            assertThat(Contracts.brokerSchemaErrors("Error", response.json())).isEmpty();
            assertThat(AuditLines.of(output, rid)).singleElement().satisfies(e -> {
                assertThat(e.path("reason").stringValue()).isEqualTo("exchange_denied");
                assertThat(e.path("outcome").stringValue()).isEqualTo("denied");
            });
        }
    }

    @Test
    void aTokenThatIsNotForTheSystemIsNotHandedOut() {
        String sub = UUID.randomUUID().toString();
        String own = tokens.subjectToken(sub, "alice");
        idp.issues(own, own, 300);
        assertThat(resolve(sub, TestTokens.newRequestId(), own).status()).as("the user's own token").isEqualTo(503);

        String other = tokens.subjectToken(sub, "alice");
        idp.issues(other, tokens.idpToken(TestTokens.IDP_ISSUER, sub, "alice", "mcp-credential-broker", "mcp-credential-broker",
                Instant.now().plusSeconds(300)), 300);
        assertThat(resolve(sub, TestTokens.newRequestId(), other).status()).as("another audience").isEqualTo(503);

        String typed = tokens.subjectToken(sub, "alice");
        idp.answers(typed, 200, "{\"access_token\":\"t-1\",\"token_type\":\"DPoP\",\"expires_in\":60}");
        assertThat(resolve(sub, TestTokens.newRequestId(), typed).status()).as("token type").isEqualTo(503);
        String issuedType = tokens.subjectToken(sub, "alice");
        idp.answers(issuedType, 200, "{\"access_token\":\"t-2\",\"token_type\":\"Bearer\",\"expires_in\":60,"
                + "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:refresh_token\"}");
        assertThat(resolve(sub, TestTokens.newRequestId(), issuedType).status()).as("issued token type").isEqualTo(503);
    }

    @Test
    void anInvalidScopeIsTheInstallationsFaultNotTheUsers(CapturedOutput output) {
        String sub = UUID.randomUUID().toString();
        String subjectToken = tokens.subjectToken(sub, "alice");
        idp.refuses(subjectToken, 400, "invalid_scope");
        String rid = TestTokens.newRequestId();
        assertThat(resolve(sub, rid, subjectToken).status()).isEqualTo(503);
        assertThat(AuditLines.of(output, rid)).singleElement()
                .satisfies(e -> assertThat(e.path("outcome").stringValue()).isEqualTo("error"));
    }

    @Test
    void whenTheIdpCannotAnswerTheCallerGets503(CapturedOutput output) {
        for (String failure : List.of("invalid_client", "unauthorized_client", "server_error", "reset", "malformed")) {
            String sub = UUID.randomUUID().toString();
            String subjectToken = tokens.subjectToken(sub, "alice");
            switch (failure) {
                case "invalid_client" -> idp.refuses(subjectToken, 401, failure);
                case "unauthorized_client" -> idp.refuses(subjectToken, 400, failure);
                case "server_error" -> idp.answers(subjectToken, 500, "{}");
                case "reset" -> idp.breaksConnection(subjectToken);
                default -> idp.answers(subjectToken, 200, "{\"access_token\":\"two words\",\"expires_in\":60}");
            }
            String rid = TestTokens.newRequestId();
            BrokerClient.Response response = resolve(sub, rid, subjectToken);
            assertThat(response.status()).as(failure).isEqualTo(503);
            assertThat(response.body()).isEqualTo("{\"error\":\"upstream_unavailable\"}");
            assertThat(AuditLines.of(output, rid)).singleElement().satisfies(e -> {
                assertThat(e.path("outcome").stringValue()).isEqualTo("error");
                assertThat(e.path("errorCode").stringValue()).isEqualTo("upstream_unavailable");
            });
        }
    }

    @Test
    void aSubjectTokenIsRefusedForSystemsThatDoNotExchange() {
        String sub = UUID.randomUUID().toString();
        String rid = TestTokens.newRequestId();
        BrokerClient.Response response = gateway.send("POST", "/v1/credentials/resolve",
                tokens.gatewayUser(sub, "alice", rid, "get_issue"), rid,
                "{\"system\":\"jira\",\"subjectToken\":\"" + tokens.subjectToken(sub, "alice") + "\"}");
        assertThat(response.status()).isEqualTo(400);
    }

    private BrokerClient.Response resolve(String sub, String rid, String subjectToken) {
        String body = subjectToken == null ? "{\"system\":\"opensearch\"}"
                : "{\"system\":\"opensearch\",\"subjectToken\":\"" + subjectToken + "\"}";
        return gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", rid, "search_logs"), rid, body);
    }

    /** A token with the right claims whose signature belongs to the payload of another token. */
    private String forgedSignature(String sub) {
        String genuine = tokens.subjectToken(sub, "alice");
        String other = tokens.subjectToken(UUID.randomUUID().toString(), "bob");
        String[] a = genuine.split("\\.");
        String[] b = other.split("\\.");
        return a[0] + "." + a[1] + "." + b[2];
    }
}
