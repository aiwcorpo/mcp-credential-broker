package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.UncheckedIOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLHandshakeException;

import org.junit.jupiter.api.AfterAll;
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

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.pubsub.RedisPubSubAdapter;
import io.lettuce.core.pubsub.StatefulRedisPubSubConnection;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import tools.jackson.databind.JsonNode;

/**
 * The broker over real mTLS against PostgreSQL, Redis (dev ACL) and OpenBao (AppRole, KV v2, Transit),
 * with a fake Jira whoami. Covers M1 of ws-06 and the M1 items of its Definition of Done.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class BrokerIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final List<String> ALL_PATS = List.of("alice-pat", "bob-pat", "carol-pat", "mallory-pat",
            "invalid-pat", "someone-elses-pat");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @LocalServerPort
    int port;

    @Autowired
    JdbcClient jdbc;

    BrokerClient gateway;
    BrokerClient bff;
    BrokerClient offboarding;
    TestTokens tokens = env.tokens;

    @BeforeEach
    void clients() {
        gateway = new BrokerClient(env.pki.clientContext(env.gatewayClient), port);
        bff = new BrokerClient(env.pki.clientContext(env.bffClient), port);
        offboarding = new BrokerClient(env.pki.clientContext(env.offboardingClient), port);
    }

    @AfterAll
    static void noResponseOtherThanResolveCarriesASecret() {
        List<BrokerClient.Response> responses = BrokerClient.recorded();
        assertThat(responses).hasSizeGreaterThan(20);
        for (BrokerClient.Response response : responses) {
            assertThat(response.header("X-Request-Id")).as("X-Request-Id on every response (CC-047)")
                    .matches("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
            if (response.status() >= 400 && response.status() != 409 && response.status() != 422) {
                assertThat(Contracts.brokerSchemaErrors("Error", response.json())).as(response.body()).isEmpty();
            }
            boolean resolveSuccess = response.raw().request().uri().getPath().equals("/v1/credentials/resolve")
                    && response.status() == 200;
            if (resolveSuccess) {
                continue;
            }
            String everything = response.body() + response.raw().headers().map();
            for (String pat : ALL_PATS) {
                assertThat(everything).as(response.raw().request().uri().getPath()).doesNotContain(pat);
            }
        }
    }

    @Test
    void storesAPatAndResolvesItForTheSameUser(CapturedOutput output) {
        String sub = newSub();
        BrokerClient.Response put = putSecret(sub, "alice", "{\"secret\":\"alice-pat\"}");
        assertThat(put.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("PutSecretResponse", put.json())).isEmpty();
        assertThat(put.json().path("status").stringValue()).isEqualTo("connected");
        assertThat(put.json().path("backendUser").stringValue()).isEqualTo("alice");
        assertThat(put.json().path("expiresAt").isNull()).isTrue();
        assertThat(put.header("Cache-Control")).isEqualTo("no-store");

        String rid = TestTokens.newRequestId();
        BrokerClient.Response resolved = resolve(sub, "alice", rid, "{\"system\":\"jira\"}");
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("ResolvedCredential", resolved.json())).isEmpty();
        assertThat(resolved.json().path("scheme").stringValue()).isEqualTo("Bearer");
        assertThat(resolved.json().path("value").stringValue()).isEqualTo("alice-pat");
        assertThat(resolved.json().path("type").stringValue()).isEqualTo("user-secret");
        assertThat(resolved.json().path("cacheTtlSeconds").asInt()).isBetween(0, 60);
        assertThat(resolved.header("Cache-Control")).isEqualTo("no-store");
        assertThat(resolved.header("Pragma")).isEqualTo("no-cache");
        assertThat(resolved.header("X-Request-Id")).isEqualTo(rid);

        Instant lastUsed = jdbc.sql("select last_used_at from connection where sub = ?").param(sub)
                .query(java.sql.Timestamp.class).single().toInstant();
        assertThat(lastUsed).isCloseTo(Instant.now(), org.assertj.core.api.Assertions.within(1, ChronoUnit.MINUTES));

        List<JsonNode> audit = auditEvents(output, rid);
        assertThat(audit).hasSize(1);
        assertThat(audit.getFirst().path("event").stringValue()).isEqualTo("credential_resolve");
        assertThat(audit.getFirst().path("outcome").stringValue()).isEqualTo("ok");
        assertThat(audit.getFirst().path("sub").stringValue()).isEqualTo(sub);
        assertThat(audit.getFirst().path("server").stringValue()).isEqualTo("mcp-jira");
        assertThat(audit.getFirst().path("credentialType").stringValue()).isEqualTo("user-secret");
        assertNoSecretsLogged(output);
    }

    @Test
    void portalRequestIdIsUsedForAuditAndEchoed(CapturedOutput output) {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response put = bff.send("PUT", "/v1/connections/jira/secret", tokens.bffUser(newSub(), "alice"), rid,
                "{\"secret\":\"alice-pat\"}");
        assertThat(put.status()).isEqualTo(200);
        assertThat(put.header("X-Request-Id")).isEqualTo(rid);
        assertThat(auditEvents(output, rid)).singleElement()
                .satisfies(e -> assertThat(e.path("event").stringValue()).isEqualTo("connection_change"));

        BrokerClient.Response invalidId = bff.send("PUT", "/v1/connections/jira/secret", tokens.bffUser(newSub(), "alice"),
                "not-a-uuid", "{\"secret\":\"alice-pat\"}");
        assertThat(invalidId.status()).isEqualTo(200);
        assertThat(invalidId.header("X-Request-Id")).isNotEqualTo("not-a-uuid");
    }

    @Test
    void storedValueIsTransitCiphertextUnderTheSubHash() {
        String sub = newSub();
        assertThat(putSecret(sub, "alice", "{\"secret\":\"alice-pat\"}").status()).isEqualTo(200);
        String path = storedPath(sub);
        var stored = env.bao("GET", path, null);
        assertThat(stored.statusCode()).isEqualTo(200);
        assertThat(stored.body()).doesNotContain("alice-pat").doesNotContain(sub);
        assertThat(Contracts.JSON.readTree(stored.body()).path("data").path("data").path("ciphertext").stringValue())
                .startsWith("vault:v1:");

        assertThat(putSecret(sub, "alice", "{\"secret\":\"alice-pat\"}").status()).isEqualTo(200);
        assertThat(storedPath(sub)).isNotEqualTo(path);
        assertThat(env.bao("GET", path, null).statusCode()).as("replaced value removed with all KV versions").isEqualTo(404);
        assertThat(env.bao("GET", storedPath(sub), null).statusCode()).isEqualTo(200);
    }

    @Test
    void ciphertextMovedToAnotherUsersPathIsRefused() {
        String alice = newSub();
        String mallory = newSub();
        assertThat(putSecret(alice, "alice", "{\"secret\":\"alice-pat\"}").status()).isEqualTo(200);
        assertThat(putSecret(mallory, "mallory", "{\"secret\":\"mallory-pat\"}").status()).isEqualTo(200);
        String aliceEntry = env.bao("GET", storedPath(alice), null).body();
        String ciphertext = Contracts.JSON.readTree(aliceEntry).path("data").path("data").path("ciphertext").stringValue();
        assertThat(env.bao("POST", storedPath(mallory), "{\"data\":{\"ciphertext\":\"" + ciphertext + "\"}}").statusCode())
                .isEqualTo(200);

        BrokerClient.Response resolved = resolve(mallory, "mallory", TestTokens.newRequestId(), "{\"system\":\"jira\"}");
        assertThat(resolved.status()).isEqualTo(503);
        assertThat(resolved.body()).isEqualTo("{\"error\":\"upstream_unavailable\"}");
    }

    @Test
    void expiringSecretReportsStatusAndExpiry() {
        String sub = newSub();
        Instant expires = Instant.now().plus(3, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        BrokerClient.Response put = putSecret(sub, "bob", "{\"secret\":\"bob-pat\",\"expiresAt\":\"" + expires + "\"}");
        assertThat(put.status()).isEqualTo(200);
        assertThat(put.json().path("status").stringValue()).isEqualTo("expiring");
        assertThat(put.json().path("expiresAt").stringValue()).isEqualTo(expires.toString());

        BrokerClient.Response resolved = resolve(sub, "bob", TestTokens.newRequestId(), "{\"system\":\"jira\"}");
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(resolved.json().path("expiresAt").stringValue()).isEqualTo(expires.toString());
        assertThat(resolved.json().path("cacheTtlSeconds").asInt()).isEqualTo(60);
    }

    @Test
    void pastExpiryIsRejected() {
        BrokerClient.Response put = putSecret(newSub(), "bob", "{\"secret\":\"bob-pat\",\"expiresAt\":\"2020-01-01T00:00:00Z\"}");
        assertThat(put.status()).isEqualTo(400);
        assertThat(put.json().path("error").stringValue()).isEqualTo("invalid_request");
    }

    @Test
    void resolveWithoutConnectionAsksForOne(CapturedOutput output) {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response resolved = resolve(newSub(), "dave", rid, "{\"system\":\"jira\"}");
        assertThat(resolved.status()).isEqualTo(409);
        assertThat(Contracts.brokerSchemaErrors("CredentialRequired", resolved.json())).isEmpty();
        assertThat(resolved.json().path("connectUrl").stringValue()).isEqualTo("https://mcp-portal.test/connections?system=jira");
        assertThat(auditEvents(output, rid)).singleElement()
                .satisfies(e -> assertThat(e.path("reason").stringValue()).isEqualTo("credential_required"));
    }

    @Test
    void anotherPersonsPatIsRejectedAndNothingIsStored(CapturedOutput output) {
        String carol = newSub();
        int whoamiBefore = env.whoamiCalls.get();
        BrokerClient.Response put = putSecret(carol, "carol", "{\"secret\":\"bob-pat\"}");
        assertThat(put.status()).isEqualTo(422);
        assertThat(Contracts.brokerSchemaErrors("PutSecretError", put.json())).isEmpty();
        assertThat(put.json().path("error").stringValue()).isEqualTo("identity_mismatch");
        assertThat(env.whoamiCalls.get()).isEqualTo(whoamiBefore + 1);
        assertThat(rows(carol)).isZero();
        assertThat(env.bao("LIST", "secret/metadata/mcp/connections/" + new SecretKey(carol, "jira", null).subHash(), null)
                .statusCode()).as("nothing stored under the user").isEqualTo(404);
        assertThat(resolve(carol, "carol", TestTokens.newRequestId(), "{\"system\":\"jira\"}").status()).isEqualTo(409);

        String alice = newSub();
        assertThat(putSecret(alice, "alice", "{\"secret\":\"alice-pat\"}").status()).isEqualTo(200);
        assertThat(putSecret(alice, "alice", "{\"secret\":\"bob-pat\"}").status()).isEqualTo(422);
        assertThat(resolve(alice, "alice", TestTokens.newRequestId(), "{\"system\":\"jira\"}").json()
                .path("value").stringValue()).isEqualTo("alice-pat");
        assertNoSecretsLogged(output);
    }

    @Test
    void secretTheSystemRejectsIsNotStored() {
        String sub = newSub();
        BrokerClient.Response invalid = putSecret(sub, "alice", "{\"secret\":\"invalid-pat\"}");
        assertThat(invalid.status()).isEqualTo(422);
        assertThat(invalid.json().path("error").stringValue()).isEqualTo("secret_invalid");

        int whoamiBefore = env.whoamiCalls.get();
        BrokerClient.Response injection = putSecret(sub, "alice", "{\"secret\":\"alice-pat\\r\\nX-Injected: 1\"}");
        assertThat(injection.status()).isEqualTo(422);
        assertThat(env.whoamiCalls.get()).isEqualTo(whoamiBefore);
        assertThat(rows(sub)).isZero();
    }

    @Test
    void portalCannotNameAnotherUser() {
        String attacker = newSub();
        String victim = newSub();
        BrokerClient.Response withSub = bff.send("PUT", "/v1/connections/jira/secret", tokens.bffUser(attacker, "mallory"),
                null, "{\"secret\":\"mallory-pat\",\"sub\":\"" + victim + "\"}");
        assertThat(withSub.status()).isEqualTo(400);

        BrokerClient.Response withQuery = bff.send("PUT", "/v1/connections/jira/secret?sub=" + victim,
                tokens.bffUser(attacker, "mallory"), null, "{\"secret\":\"mallory-pat\"}");
        assertThat(withQuery.status()).isEqualTo(200);
        assertThat(rows(victim)).isZero();
        assertThat(rows(attacker)).isOne();

        BrokerClient.Response otherPath = bff.send("PUT", "/v1/connections/" + victim + "/jira/secret",
                tokens.bffUser(attacker, "mallory"), null, "{\"secret\":\"mallory-pat\"}");
        assertThat(otherPath.status()).isEqualTo(404);
        assertThat(resolve(victim, "victim", TestTokens.newRequestId(), "{\"system\":\"jira\"}").status()).isEqualTo(409);
    }

    @Test
    void portalCannotResolveAndGatewayCannotStore() {
        String sub = newSub();
        assertThat(bff.send("POST", "/v1/credentials/resolve", tokens.bffUser(sub, "alice"), TestTokens.newRequestId(),
                "{\"system\":\"jira\"}").status()).isEqualTo(403);
        String rid = TestTokens.newRequestId();
        assertThat(gateway.send("PUT", "/v1/connections/jira/secret", tokens.gatewayUser(sub, "alice", rid), rid,
                "{\"secret\":\"alice-pat\"}").status()).isEqualTo(403);
        assertThat(offboarding.send("POST", "/v1/credentials/resolve", null, null, "{\"system\":\"jira\"}").status())
                .isEqualTo(403);
        assertThat(offboarding.send("GET", "/v1/systems", null, null, null).status()).isEqualTo(403);
        assertThat(rows(sub)).isZero();
    }

    @Test
    void certificateFromAnotherCaIsRefusedDuringHandshake() {
        BrokerClient foreign = new BrokerClient(env.pki.clientContext(env.foreignGateway), port);
        assertThatThrownBy(() -> foreign.send("GET", "/v1/systems", null, null, null))
                .isInstanceOf(UncheckedIOException.class)
                .satisfies(e -> assertThat(e.getCause()).isInstanceOfAny(SSLHandshakeException.class, java.io.IOException.class));
    }

    @Test
    void bffTokenMustBeForTheBrokerAndFromTheBff() {
        String sub = newSub();
        String secret = "{\"secret\":\"alice-pat\"}";
        assertThat(bff.send("PUT", "/v1/connections/jira/secret", null, null, secret).status()).isEqualTo(401);
        assertThat(bff.send("PUT", "/v1/connections/jira/secret", tokens.bff(sub, "alice", "mcp-gateway", "mcp-credential-broker"),
                null, secret).status()).isEqualTo(401);
        assertThat(bff.send("PUT", "/v1/connections/jira/secret", tokens.bff(sub, "alice", "mcp-portal-bff", "mcp-gateway-admin"),
                null, secret).status()).isEqualTo(401);
        String rid = TestTokens.newRequestId();
        assertThat(bff.send("PUT", "/v1/connections/jira/secret", tokens.gatewayUser(sub, "alice", rid), rid, secret)
                .status()).isEqualTo(401);
        assertThat(rows(sub)).isZero();
    }

    @Test
    void gatewayTokenRules() {
        String sub = newSub();
        String body = "{\"system\":\"jira\"}";
        assertThat(gateway.send("POST", "/v1/credentials/resolve", null, TestTokens.newRequestId(), body).status()).isEqualTo(401);

        String serviceRid = TestTokens.newRequestId();
        assertThat(gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayService(serviceRid), serviceRid, body)
                .status()).isEqualTo(401);

        String rid = TestTokens.newRequestId();
        String token = tokens.gatewayUser(sub, "alice", rid);
        assertThat(gateway.send("POST", "/v1/credentials/resolve", token, TestTokens.newRequestId(), body).status())
                .as("rid differs from X-Request-Id").isEqualTo(401);

        String rid2 = TestTokens.newRequestId();
        String once = tokens.gatewayUser(sub, "alice", rid2);
        assertThat(gateway.send("POST", "/v1/credentials/resolve", once, rid2, body).status()).isEqualTo(409);
        assertThat(gateway.send("POST", "/v1/credentials/resolve", once, rid2, body).status()).as("replayed jti").isEqualTo(401);

        String bffToken = tokens.bffUser(sub, "alice");
        assertThat(gateway.send("POST", "/v1/credentials/resolve", bffToken, TestTokens.newRequestId(), body).status())
                .isEqualTo(401);

        String noTool = TestTokens.newRequestId();
        assertThat(gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", noTool, null), noTool, body)
                .status()).as("resolve requires tool (CC-038)").isEqualTo(401);
        String withTool = TestTokens.newRequestId();
        assertThat(gateway.send("GET", "/v1/systems", tokens.gatewayUser(sub, "alice", withTool), withTool, null).status())
                .as("tool not allowed outside resolve").isEqualTo(401);
        String userNoTool = TestTokens.newRequestId();
        assertThat(gateway.send("GET", "/v1/systems", tokens.gatewayUser(sub, "alice", userNoTool, null), userNoTool, null)
                .status()).isEqualTo(200);
    }

    @Test
    void systemsForGatewayServiceTokenAndPortal() {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response fromGateway = gateway.send("GET", "/v1/systems", tokens.gatewayService(rid), rid, null);
        assertThat(fromGateway.status()).isEqualTo(200);
        assertThat(fromGateway.json().isArray()).isTrue();
        for (JsonNode system : fromGateway.json()) {
            assertThat(Contracts.brokerSchemaErrors("SystemInfo", system)).isEmpty();
        }
        assertThat(fromGateway.json().get(0).path("system").stringValue()).isEqualTo("jira");
        assertThat(fromGateway.json().get(0).path("supportedTypes").get(0).stringValue()).isEqualTo("user-secret");

        BrokerClient.Response fromPortal = bff.send("GET", "/v1/systems", tokens.bffUser(newSub(), "alice"), null, null);
        assertThat(fromPortal.status()).isEqualTo(200);
        assertThat(fromPortal.body()).isEqualTo(fromGateway.body());
    }

    @Test
    void malformedRequestsAreRejectedWithoutEcho(CapturedOutput output) {
        String sub = newSub();
        BrokerClient.Response unknownSystem = putSecret(sub, "alice", "{\"secret\":\"alice-pat\"}", "jirax");
        assertThat(unknownSystem.status()).isEqualTo(400);
        BrokerClient.Response notJson = putSecret(sub, "alice", "{\"secret\": alice-pat");
        assertThat(notJson.status()).isEqualTo(400);
        assertThat(notJson.body()).isEqualTo("{\"error\":\"invalid_request\"}");
        BrokerClient.Response notConfigured = putSecret(sub, "alice", "{\"secret\":\"alice-pat\"}", "gitlab");
        assertThat(notConfigured.status()).isEqualTo(400);
        String rid = TestTokens.newRequestId();
        assertThat(gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", rid), rid,
                "{\"system\":\"jira\",\"extra\":1}").status()).isEqualTo(400);
        assertThat(gateway.send("GET", "/v1/connections", null, null, null).status()).isEqualTo(404);
        assertThat(rows(sub)).isZero();
        assertNoSecretsLogged(output);
    }

    @Test
    void replacingASecretPublishesInvalidation() throws InterruptedException {
        BlockingQueue<String> messages = new LinkedBlockingQueue<>();
        RedisClient client = RedisClient.create(RedisURI.builder()
                .withHost(env.redis.getHost()).withPort(env.redis.getMappedPort(6379))
                .withAuthentication("admin", TestEnvironment.REDIS_ADMIN_PASSWORD.toCharArray()).build());
        try (StatefulRedisPubSubConnection<String, String> connection = client.connectPubSub()) {
            connection.addListener(new RedisPubSubAdapter<>() {
                @Override
                public void message(String channel, String message) {
                    messages.add(message);
                }
            });
            connection.sync().subscribe("credential.invalidated");
            String sub = newSub();
            assertThat(putSecret(sub, "alice", "{\"secret\":\"alice-pat\"}").status()).isEqualTo(200);
            assertThat(messages.poll(500, TimeUnit.MILLISECONDS)).as("first connection invalidates nothing").isNull();
            assertThat(putSecret(sub, "alice", "{\"secret\":\"alice-pat\"}").status()).isEqualTo(200);
            String event = messages.poll(5, TimeUnit.SECONDS);
            assertThat(event).isNotNull();
            JsonNode parsed = Contracts.JSON.readTree(event);
            assertThat(Contracts.schemaErrors("schemas/credential-invalidated-event.schema.json", parsed)).isEmpty();
            assertThat(parsed.path("sub").stringValue()).isEqualTo(sub);
            assertThat(parsed.path("system").stringValue()).isEqualTo("jira");
        } finally {
            client.shutdown();
        }
    }

    @Test
    void chunkedBodyOverTheLimitIsNotRead() {
        String sub = newSub();
        byte[] body = ("{\"secret\":\"" + "a".repeat(200_000) + "\"}").getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        int whoamiBefore = env.whoamiCalls.get();
        BrokerClient.Response response = bff.sendChunked("PUT", "/v1/connections/jira/secret", tokens.bffUser(sub, "alice"), body);
        assertThat(response.raw().request().headers().firstValue("Content-Length")).isEmpty();
        assertThat(response.status()).isEqualTo(400);
        assertThat(env.whoamiCalls.get()).isEqualTo(whoamiBefore);
        assertThat(rows(sub)).isZero();
    }

    @Test
    void unknownPathsAndMethodsGetNoHandler() {
        String bffToken = tokens.bffUser(newSub(), "alice");
        for (String path : List.of("/v1/credentials/../systems", "/v1/%2e%2e/systems", "/v1/systems;x=1", "//v1/systems",
                "/error", "/actuator/env", "/v1/connections", "/v1/admin/users/x/purge")) {
            int status = bff.send("GET", path, bffToken, null, null).status();
            assertThat(status).as(path).isIn(400, 404);
        }
        BrokerClient.Response missing = bff.send("GET", "/v1/nothing", bffToken, null, null);
        assertThat(missing.json().path("error").stringValue()).isEqualTo("not_found_or_denied");
        assertThat(bff.send("OPTIONS", "/v1/systems", bffToken, null, null).status()).isEqualTo(404);
        assertThat(bff.send("DELETE", "/v1/systems", bffToken, null, null).status()).isEqualTo(404);
    }

    @Test
    void rejectionsBeforeTheServiceAreAudited(CapturedOutput output) {
        String forbidden = TestTokens.newRequestId();
        assertThat(bff.send("POST", "/v1/credentials/resolve", tokens.bffUser(newSub(), "alice"), forbidden,
                "{\"system\":\"jira\"}").status()).isEqualTo(403);
        assertThat(auditEvents(output, forbidden)).singleElement()
                .satisfies(e -> assertThat(e.path("reason").stringValue()).isEqualTo("forbidden_cn"));

        String sub = newSub();
        String malformed = TestTokens.newRequestId();
        assertThat(gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", malformed), malformed,
                "{\"system\":\"jira\",\"extra\":1}").status()).isEqualTo(400);
        assertThat(auditEvents(output, malformed)).singleElement().satisfies(e -> {
            assertThat(e.path("reason").stringValue()).isEqualTo("invalid_request");
            assertThat(e.path("sub").stringValue()).isEqualTo(sub);
        });

        String unknownSystem = TestTokens.newRequestId();
        assertThat(gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", unknownSystem), unknownSystem,
                "{\"system\":\"jirax\"}").status()).isEqualTo(400);
        assertThat(auditEvents(output, unknownSystem)).singleElement()
                .satisfies(e -> assertThat(e.has("server")).isFalse());

        String subjectToken = TestTokens.newRequestId();
        assertThat(gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", subjectToken), subjectToken,
                "{\"system\":\"jira\",\"subjectToken\":\"exchanged\"}").status()).isEqualTo(400);
        assertThat(auditEvents(output, subjectToken)).hasSize(1);
    }

    @Test
    void redisOutageFailsClosed(CapturedOutput output) {
        String sub = newSub();
        assertThat(putSecret(sub, "alice", "{\"secret\":\"alice-pat\"}").status()).isEqualTo(200);
        String rid = TestTokens.newRequestId();
        String token = tokens.gatewayUser(sub, "alice", rid);
        BrokerClient.Response resolved;
        pause(env.redis);
        try {
            resolved = gateway.send("POST", "/v1/credentials/resolve", token, rid, "{\"system\":\"jira\"}");
        } finally {
            unpause(env.redis);
        }
        assertThat(resolved.status()).isEqualTo(503);
        assertThat(resolved.body()).isEqualTo("{\"error\":\"upstream_unavailable\"}");
        assertThat(auditEvents(output, rid)).singleElement()
                .satisfies(e -> assertThat(e.path("reason").stringValue()).isEqualTo("jti_store_unavailable"));
    }

    @Test
    void databaseOutageFailsClosed(CapturedOutput output) {
        String rid = TestTokens.newRequestId();
        String token = tokens.gatewayUser(newSub(), "alice", rid);
        BrokerClient.Response resolved;
        pause(env.postgres);
        try {
            resolved = gateway.send("POST", "/v1/credentials/resolve", token, rid, "{\"system\":\"jira\"}");
        } finally {
            unpause(env.postgres);
        }
        assertThat(resolved.status()).isEqualTo(503);
        assertThat(auditEvents(output, rid)).singleElement()
                .satisfies(e -> assertThat(e.path("reason").stringValue()).isEqualTo("database_unavailable"));
    }

    @Test
    void httpLayerStaysAtInfoEvenWhenDebugIsConfigured() {
        ch.qos.logback.classic.Logger web = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
                .getLogger("org.springframework.web.servlet.DispatcherServlet");
        ch.qos.logback.classic.Level previous = web.getLevel();
        web.setLevel(ch.qos.logback.classic.Level.DEBUG);
        try {
            assertThat(web.isDebugEnabled()).as("logback-spring.xml installs HttpLayerDebugGuard").isFalse();
            assertThat(web.isInfoEnabled()).isTrue();
        } finally {
            web.setLevel(previous);
        }
    }

    private static void pause(org.testcontainers.containers.GenericContainer<?> container) {
        container.getDockerClient().pauseContainerCmd(container.getContainerId()).exec();
    }

    private static void unpause(org.testcontainers.containers.GenericContainer<?> container) {
        container.getDockerClient().unpauseContainerCmd(container.getContainerId()).exec();
    }

    private BrokerClient.Response putSecret(String sub, String username, String body) {
        return putSecret(sub, username, body, "jira");
    }

    private BrokerClient.Response putSecret(String sub, String username, String body, String system) {
        return bff.send("PUT", "/v1/connections/" + system + "/secret", tokens.bffUser(sub, username), null, body);
    }

    private BrokerClient.Response resolve(String sub, String username, String rid, String body) {
        return gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, username, rid), rid, body);
    }

    private String storedPath(String sub) {
        String version = jdbc.sql("select secret_version from connection where sub = ?").param(sub).query(String.class).single();
        return "secret/data/mcp/connections/" + new SecretKey(sub, "jira", version).relativePath();
    }

    private long rows(String sub) {
        return jdbc.sql("select count(*) from connection where sub = ?").param(sub).query(Long.class).single();
    }

    private static String newSub() {
        return UUID.randomUUID().toString();
    }

    /** Broker audit lines (C8) of one request, each validated against audit-event.schema.json. */
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

    private static void assertNoSecretsLogged(CapturedOutput output) {
        for (String pat : ALL_PATS) {
            assertThat(output.getAll()).doesNotContain(pat);
        }
    }
}
