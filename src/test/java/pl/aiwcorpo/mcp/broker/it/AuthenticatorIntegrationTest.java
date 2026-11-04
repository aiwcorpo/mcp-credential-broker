package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpResponse;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;

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

import pl.aiwcorpo.mcp.broker.authenticator.Base32;
import pl.aiwcorpo.mcp.broker.authenticator.Totp;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import tools.jackson.databind.JsonNode;

/**
 * The authenticator of M3 over real mTLS against PostgreSQL, Redis and OpenBao Transit: registration by the BFF,
 * verification by the gateway, the limits and their atomicity under parallel requests, the storage of the seed,
 * and who may call what. Codes are computed from the seed returned by the enrollment, as an authenticator app does.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class AuthenticatorIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final List<String> SEEDS = new ArrayList<>();
    private static final String TOOL = "delete_issue";

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
    static void onlyTheEnrollmentResponseCarriesTheSeed() {
        assertThat(SEEDS).isNotEmpty();
        for (BrokerClient.Response response : BrokerClient.recorded()) {
            String everything = response.body() + response.raw().headers().map();
            for (String seed : SEEDS) {
                if (everything.contains(seed)) {
                    assertThat(response.raw().request().uri().getPath()).isEqualTo("/v1/authenticator/enrollment");
                    assertThat(response.status()).isEqualTo(201);
                }
            }
        }
    }

    @Test
    void parallelConfirmsOfOneEnrollmentLeaveOneRegistrationThatCanVerify() throws Exception {
        for (int parallelism : new int[] {2, 4}) {
            for (int round = 0; round < 10; round++) {
                String sub = newSub();
                String bffToken = tokens.bffUser(sub, "ivan");
                Enrolled enrolled = startOnly(bffToken);
                String code = currentCode(enrolled.seed);
                List<String> statuses = parallel(parallelism, () -> String.valueOf(confirm(bffToken, enrolled.id, code).status()));

                assertThat(count(statuses, "200")).as(parallelism + " parallel confirms: " + statuses).isEqualTo(1);
                assertThat(statuses).containsOnly("200", "422");
                assertThat(gatewayStatus(sub).json().path("state").stringValue()).isEqualTo("active");
                assertThat(verify(sub, nextCode(enrolled.seed)).json().path("result").stringValue())
                        .as("the registration that won has its seed").isEqualTo("ok");
            }
        }
    }

    // Registration ---------------------------------------------------------------------------------------

    @Test
    void registrationFlowAndStorageOfTheSeed(CapturedOutput output) {
        String sub = newSub();
        String bffToken = tokens.bffUser(sub, "alice");

        BrokerClient.Response none = bff.send("GET", "/v1/authenticator", bffToken, null, null);
        assertThat(none.status()).isEqualTo(200);
        assertThat(none.json().path("state").stringValue()).isEqualTo("none");
        assertThat(Contracts.brokerSchemaErrors("AuthenticatorStatus", none.json())).isEmpty();

        String requestId = TestTokens.newRequestId();
        BrokerClient.Response started = bff.send("POST", "/v1/authenticator/enrollment", bffToken, requestId, null);
        assertThat(started.status()).isEqualTo(201);
        assertThat(started.header("Cache-Control")).isEqualTo("no-store");
        assertThat(started.header("Pragma")).isEqualTo("no-cache");
        assertThat(Contracts.brokerSchemaErrors("AuthenticatorEnrollment", started.json())).isEmpty();
        String secret = started.json().path("secret").stringValue();
        SEEDS.add(secret);
        assertThat(started.json().path("otpauthUri").stringValue()).isEqualTo(
                "otpauth://totp/MCP%20Platform:alice?secret=" + secret + "&issuer=MCP%20Platform&algorithm=SHA1&digits=6&period=30");
        Instant expiresAt = Instant.parse(started.json().path("expiresAt").stringValue());
        assertThat(expiresAt).isBetween(Instant.now().plusSeconds(570), Instant.now().plusSeconds(601));
        String enrollmentId = started.json().path("enrollmentId").stringValue();

        assertThat(bff.send("GET", "/v1/authenticator", bffToken, null, null).json().path("state").stringValue()).isEqualTo("none");

        byte[] seed = Base32.decode(secret);
        BrokerClient.Response wrong = confirm(bffToken, enrollmentId, wrongCode(seed));
        assertThat(wrong.status()).isEqualTo(422);
        assertThat(wrong.json().path("error").stringValue()).isEqualTo("invalid_code");
        assertThat(Contracts.brokerSchemaErrors("AuthenticatorEnrollmentError", wrong.json())).isEmpty();

        BrokerClient.Response active = confirm(bffToken, enrollmentId, currentCode(seed));
        assertThat(active.status()).isEqualTo(200);
        assertThat(active.json().path("state").stringValue()).isEqualTo("active");
        assertThat(Contracts.brokerSchemaErrors("AuthenticatorStatus", active.json())).isEmpty();

        assertThat(gatewayStatus(sub).json().path("state").stringValue()).isEqualTo("active");
        assertThat(bff.send("POST", "/v1/authenticator/enrollment", bffToken, null, null).status()).isEqualTo(409);

        assertThat(verify(sub, nextCode(seed)).json().path("result").stringValue()).isEqualTo("ok");
        BrokerClient.Response replay = verify(sub, nextCode(seed));
        assertThat(replay.json().path("result").stringValue()).isEqualTo("replayed");
        assertThat(replay.header("Cache-Control")).isEqualTo("no-store");
        assertThat(Contracts.brokerSchemaErrors("AuthenticatorVerifyResult", replay.json())).isEmpty();
        assertThat(gatewayStatus(sub).json().path("lastUsedAt").isString()).isTrue();

        // Storage: ciphertext in KV under the contract path, the record names its owner, the database has no seed.
        String hash = SecretKey.hashOf(sub);
        HttpResponse<String> kv = env.bao("GET", "secret/data/mcp/authenticators/" + hash, null);
        assertThat(kv.statusCode()).isEqualTo(200);
        String ciphertext = Contracts.JSON.readTree(kv.body()).path("data").path("data").path("ciphertext").stringValue();
        assertThat(ciphertext).startsWith("vault:v1:");
        assertThat(kv.body()).doesNotContain(secret).doesNotContain(Base64.getEncoder().encodeToString(seed));
        HttpResponse<String> decrypted = env.bao("POST", "transit/decrypt/mcp-authenticators",
                Contracts.JSON.createObjectNode().put("ciphertext", ciphertext).toString());
        String record = new String(Base64.getDecoder().decode(
                Contracts.JSON.readTree(decrypted.body()).path("data").path("plaintext").stringValue()));
        assertThat(Contracts.JSON.readTree(record).path("sub").stringValue()).isEqualTo(sub);
        assertThat(env.bao("GET", "secret/data/mcp/authenticators/" + hash + "/pending", null).statusCode()).isEqualTo(404);
        String metadata = jdbc.sql("select cast(a as text) from authenticator a where sub = :sub").param("sub", sub)
                .query(String.class).single()
                + jdbc.sql("select coalesce(string_agg(cast(f as text), ','), '') from authenticator_failure f where sub = :sub")
                        .param("sub", sub).query(String.class).single();
        assertThat(metadata).doesNotContain(secret).doesNotContain(Base64.getEncoder().encodeToString(seed));

        assertThat(output.getAll()).doesNotContain(secret).doesNotContain("otpauth://");
        List<JsonNode> events = auditEvents(output, requestId);
        assertThat(events).extracting(e -> e.path("reason").stringValue()).containsExactly("authenticator_enrollment_started");
        assertThat(events.getFirst().path("event").stringValue()).isEqualTo("authenticator");
        assertThat(events.getFirst().path("outcome").stringValue()).isEqualTo("ok");
    }

    @Test
    void threeWrongCodesDestroyTheEnrollment() {
        String sub = newSub();
        String bffToken = tokens.bffUser(sub, "bob");
        Enrolled enrolled = startOnly(bffToken);

        assertThat(confirm(bffToken, "enr_" + "x".repeat(22), currentCode(enrolled.seed)).json().path("error").stringValue())
                .isEqualTo("enrollment_invalid");
        assertThat(confirm(bffToken, enrolled.id, wrongCode(enrolled.seed)).json().path("error").stringValue()).isEqualTo("invalid_code");
        assertThat(confirm(bffToken, enrolled.id, wrongCode(enrolled.seed)).json().path("error").stringValue()).isEqualTo("invalid_code");
        BrokerClient.Response third = confirm(bffToken, enrolled.id, wrongCode(enrolled.seed));
        assertThat(third.status()).isEqualTo(422);
        assertThat(third.json().path("error").stringValue()).isEqualTo("enrollment_invalid");

        assertThat(env.bao("GET", "secret/data/mcp/authenticators/" + SecretKey.hashOf(sub) + "/pending", null).statusCode())
                .isEqualTo(404);
        assertThat(confirm(bffToken, enrolled.id, currentCode(enrolled.seed)).json().path("error").stringValue())
                .isEqualTo("enrollment_invalid");
        assertThat(bff.send("GET", "/v1/authenticator", bffToken, null, null).json().path("state").stringValue()).isEqualTo("none");
        // The wrong enrollment codes are not wrong codes of the verification limit.
        assertThat(jdbc.sql("select count(*) from authenticator_failure where sub = :sub").param("sub", sub).query(Integer.class).single())
                .isZero();
    }

    @Test
    void startingAgainReplacesThePendingEnrollmentAndIsRateLimited() {
        String sub = newSub();
        String bffToken = tokens.bffUser(sub, "carol");
        Enrolled first = startOnly(bffToken);
        Enrolled second = startOnly(bffToken);
        assertThat(second.id).isNotEqualTo(first.id);
        assertThat(confirm(bffToken, first.id, currentCode(first.seed)).json().path("error").stringValue()).isEqualTo("enrollment_invalid");
        // A refused confirmation of the old id must not have touched the new one.
        assertThat(confirm(bffToken, second.id, currentCode(second.seed)).status()).isEqualTo(200);

        String other = tokens.bffUser(newSub(), "dave");
        for (int i = 0; i < 10; i++) {
            BrokerClient.Response start = bff.send("POST", "/v1/authenticator/enrollment", other, null, null);
            assertThat(start.status()).isEqualTo(201);
            SEEDS.add(start.json().path("secret").stringValue());
        }
        BrokerClient.Response limited = bff.send("POST", "/v1/authenticator/enrollment", other, null, null);
        assertThat(limited.status()).isEqualTo(429);
        assertThat(limited.json().path("error").stringValue()).isEqualTo("rate_limited");
    }

    // Verification ---------------------------------------------------------------------------------------

    @Test
    void usersDoNotSeeEachOthersRegistration() {
        Registered alice = register("alice");
        String bobSub = newSub();
        assertThat(gatewayStatus(bobSub).json().path("state").stringValue()).isEqualTo("none");
        assertThat(verify(bobSub, nextCode(alice.seed)).json().path("result").stringValue()).isEqualTo("not_registered");
        assertThat(verify(alice.sub, nextCode(alice.seed)).json().path("result").stringValue()).isEqualTo("ok");
        assertThat(gw("POST", "/v1/authenticator/verify", bobSub,
                "{\"code\":\"123456\",\"sub\":\"" + alice.sub + "\"}").status()).isEqualTo(400);
    }

    @Test
    void malformedCodesAreRefusedAndCountNowhere() {
        Registered user = register("erin");
        for (String code : List.of("12345", "1234567", " 12345", "12345a", "")) {
            assertThat(gw("POST", "/v1/authenticator/verify", user.sub, "{\"code\":\"" + code + "\"}").status()).as(code).isEqualTo(400);
        }
        assertThat(gw("POST", "/v1/authenticator/verify", user.sub, "{}").status()).isEqualTo(400);
        assertThat(jdbc.sql("select count(*) from authenticator_failure where sub = :sub").param("sub", user.sub)
                .query(Integer.class).single()).isZero();
    }

    /**
     * The result of a verify that was evaluated. A parallel verify of the same user on one instance is refused at once
     * with 503 (nothing is evaluated or counted), so a client that needs a verdict asks again.
     */
    private String answered(String sub, String code) throws InterruptedException {
        long deadline = System.nanoTime() + 30_000_000_000L;
        BrokerClient.Response response;
        do {
            response = verify(sub, code);
            if (response.status() != 503) {
                break;
            }
            Thread.sleep(10);
        } while (System.nanoTime() < deadline);
        assertThat(response.status()).as(response.body()).isEqualTo(200);
        return response.json().path("result").stringValue();
    }

    @Test
    void fiftyParallelWrongCodesGiveExactlyFiveChecks() throws Exception {
        Registered user = register("frank");
        String wrong = wrongCode(user.seed);
        List<String> results = parallel(50, () -> answered(user.sub, wrong));

        assertThat(count(results, "invalid")).isEqualTo(5);
        assertThat(count(results, "locked")).isEqualTo(45);
        assertThat(jdbc.sql("select count(*) from authenticator_failure where sub = :sub").param("sub", user.sub)
                .query(Integer.class).single()).isEqualTo(5);

        BrokerClient.Response locked = verify(user.sub, nextCode(user.seed));
        assertThat(locked.json().path("result").stringValue()).isEqualTo("locked");
        assertThat(locked.json().path("retryAfterSeconds").asLong()).isBetween(800L, 900L);
        assertThat(Contracts.brokerSchemaErrors("AuthenticatorVerifyResult", locked.json())).isEmpty();
        BrokerClient.Response status = gatewayStatus(user.sub);
        assertThat(status.json().path("state").stringValue()).isEqualTo("active");
        assertThat(status.json().path("lockedUntil").isString()).isTrue();
    }

    @Test
    void parallelWrongCodesDisableTheAuthenticatorExactlyOnce(CapturedOutput output) throws Exception {
        Registered user = register("grace");
        Instant earlier = Instant.now().minus(2, ChronoUnit.HOURS);
        for (int i = 0; i < 15; i++) {
            jdbc.sql("insert into authenticator_failure (sub, at, in_short_window) values (:sub, :at, false)")
                    .param("sub", user.sub).param("at", Timestamp.from(earlier.plusSeconds(i))).update();
        }
        String wrong = wrongCode(user.seed);
        List<String> results = parallel(50, () -> answered(user.sub, wrong));

        assertThat(count(results, "invalid")).isEqualTo(5);
        assertThat(count(results, "locked") + count(results, "disabled")).isEqualTo(45);
        BrokerClient.Response status = gatewayStatus(user.sub);
        assertThat(status.json().path("state").stringValue()).isEqualTo("disabled");
        assertThat(status.json().path("disabledReason").stringValue()).isEqualTo("daily_failure_limit");
        assertThat(Contracts.brokerSchemaErrors("AuthenticatorStatus", status.json())).isEmpty();
        assertThat(verify(user.sub, nextCode(user.seed)).json().path("result").stringValue()).isEqualTo("disabled");
        long disabledEvents = output.getAll().lines()
                .filter(line -> line.startsWith("{") && line.contains("\"reason\":\"authenticator_disabled\"")
                        && line.contains(user.sub))
                .count();
        assertThat(disabledEvents).isEqualTo(1);

        // Registering again is the way out; the lock of the user stays.
        String bffToken = tokens.bffUser(user.sub, "grace");
        Enrolled again = startOnly(bffToken);
        assertThat(confirm(bffToken, again.id, currentCode(again.seed)).status()).isEqualTo(200);
        BrokerClient.Response after = gatewayStatus(user.sub);
        assertThat(after.json().path("state").stringValue()).isEqualTo("active");
        assertThat(after.json().path("lockedUntil").isString()).isTrue();
        assertThat(verify(user.sub, nextCode(again.seed)).json().path("result").stringValue()).isEqualTo("locked");
    }

    @Test
    void theSameValidCodeInParallelIsAcceptedOnce() throws Exception {
        Registered user = register("heidi");
        String code = nextCode(user.seed);
        List<String> results = parallel(20, () -> answered(user.sub, code));
        assertThat(count(results, "ok")).isEqualTo(1);
        assertThat(count(results, "replayed")).isGreaterThanOrEqualTo(1);
        assertThat(results).containsOnly("ok", "replayed", "locked");
    }

    @Test
    void invalidatedCodesAreBurnedAndNotCounted(CapturedOutput output) {
        Registered user = register("ivan");
        // Taken before the burn so a TOTP step that rolls over meanwhile cannot move these codes past the burned range.
        long stepBeforeBurn = Totp.stepOf(Instant.now());
        String requestId = TestTokens.newRequestId();
        BrokerClient.Response burn = gateway.send("POST", "/v1/authenticator/invalidate-codes",
                tokens.gatewayUser(user.sub, "ivan", requestId, TOOL), requestId, null);
        assertThat(burn.status()).isEqualTo(204);
        assertThat(gw("POST", "/v1/authenticator/invalidate-codes", user.sub, null).status())
                .isEqualTo(204);

        for (int i = 0; i < 10; i++) {
            assertThat(verify(user.sub, Totp.code(user.seed, stepBeforeBurn + 1)).json().path("result").stringValue())
                    .isEqualTo("burned");
        }
        assertThat(verify(user.sub, Totp.code(user.seed, stepBeforeBurn)).json().path("result").stringValue()).isEqualTo("burned");
        assertThat(jdbc.sql("select count(*) from authenticator_failure where sub = :sub").param("sub", user.sub)
                .query(Integer.class).single()).isZero();
        assertThat(gatewayStatus(user.sub).json().has("lockedUntil")).isFalse();
        assertThat(auditEvents(output, requestId)).extracting(e -> e.path("reason").stringValue()).containsExactly("totp_steps_burned");

        String unregistered = newSub();
        assertThat(gw("POST", "/v1/authenticator/invalidate-codes", unregistered, null).status())
                .isEqualTo(204);
    }

    // Removal, reset, lock ownership ---------------------------------------------------------------------

    @Test
    void removalAndResetDeleteTheSeedButNotTheLock(CapturedOutput output) {
        Registered user = register("judy");
        String bffToken = tokens.bffUser(user.sub, "judy");
        String wrong = wrongCode(user.seed);
        for (int i = 0; i < 5; i++) {
            verify(user.sub, wrong);
        }
        assertThat(gatewayStatus(user.sub).json().path("lockedUntil").isString()).isTrue();

        String requestId = TestTokens.newRequestId();
        assertThat(bff.send("DELETE", "/v1/authenticator", bffToken, requestId, null).status()).isEqualTo(204);
        assertThat(bff.send("DELETE", "/v1/authenticator", bffToken, null, null).status()).isEqualTo(204);
        String hash = SecretKey.hashOf(user.sub);
        assertThat(env.bao("GET", "secret/data/mcp/authenticators/" + hash, null).statusCode()).isEqualTo(404);
        BrokerClient.Response status = gatewayStatus(user.sub);
        assertThat(status.json().path("state").stringValue()).isEqualTo("none");
        assertThat(status.json().path("lockedUntil").isString()).isTrue();
        assertThat(verify(user.sub, nextCode(user.seed)).json().path("result").stringValue()).isEqualTo("not_registered");
        assertThat(auditEvents(output, requestId)).extracting(e -> e.path("reason").stringValue()).containsExactly("authenticator_removed");

        Enrolled again = startOnly(bffToken);
        assertThat(confirm(bffToken, again.id, currentCode(again.seed)).status()).isEqualTo(200);
        assertThat(verify(user.sub, nextCode(again.seed)).json().path("result").stringValue()).isEqualTo("locked");

        String resetId = TestTokens.newRequestId();
        assertThat(offboarding.send("POST", "/v1/admin/users/" + user.sub + "/authenticator/reset", null, resetId, null).status())
                .isEqualTo(204);
        assertThat(offboarding.send("POST", "/v1/admin/users/" + user.sub + "/authenticator/reset", null, null, null).status())
                .isEqualTo(204);
        assertThat(env.bao("GET", "secret/data/mcp/authenticators/" + hash, null).statusCode()).isEqualTo(404);
        BrokerClient.Response afterReset = gatewayStatus(user.sub);
        assertThat(afterReset.json().path("state").stringValue()).isEqualTo("none");
        assertThat(afterReset.json().path("lockedUntil").isString()).isTrue();
        List<JsonNode> resetEvents = auditEvents(output, resetId);
        assertThat(resetEvents).extracting(e -> e.path("reason").stringValue()).containsExactly("authenticator_reset_by_admin");
        assertThat(resetEvents.getFirst().path("sub").stringValue()).isEqualTo(user.sub);
    }

    @Test
    void aSeedCopiedToAnotherUsersPathIsNotUsable() {
        Registered alice = register("karl");
        Registered mallory = register("mallory");
        String aliceCiphertext = Contracts.JSON
                .readTree(env.bao("GET", "secret/data/mcp/authenticators/" + SecretKey.hashOf(alice.sub), null).body())
                .path("data").path("data").path("ciphertext").stringValue();
        env.bao("POST", "secret/data/mcp/authenticators/" + SecretKey.hashOf(mallory.sub),
                Contracts.JSON.createObjectNode().set("data", Contracts.JSON.createObjectNode().put("ciphertext", aliceCiphertext)).toString());

        BrokerClient.Response response = verify(mallory.sub, nextCode(alice.seed));
        assertThat(response.status()).isEqualTo(503);
        assertThat(response.body()).doesNotContain("result");
    }

    @Test
    void aPendingSeedCopiedOverTheActiveOneIsNotUsable() {
        Registered user = register("rupert");
        String bffToken = tokens.bffUser(user.sub, "rupert");
        // A registration cannot be started while active, so take a second user's pending seed and put it on this path.
        String other = newSub();
        Enrolled enrolled = startOnly(tokens.bffUser(other, "sybil"));
        String pendingCiphertext = Contracts.JSON
                .readTree(env.bao("GET", "secret/data/mcp/authenticators/" + SecretKey.hashOf(other) + "/pending", null).body())
                .path("data").path("data").path("ciphertext").stringValue();
        assertThat(enrolled.seed).isNotNull();
        env.bao("POST", "secret/data/mcp/authenticators/" + SecretKey.hashOf(user.sub),
                Contracts.JSON.createObjectNode().set("data", Contracts.JSON.createObjectNode().put("ciphertext", pendingCiphertext)).toString());

        assertThat(verify(user.sub, nextCode(user.seed)).status()).isEqualTo(503);
        assertThat(bff.send("GET", "/v1/authenticator", bffToken, null, null).json().path("state").stringValue()).isEqualTo("active");
    }

    @Test
    void aSeedOfAnotherRegistrationOfTheSameUserIsNotUsable() {
        Registered user = register("trent");
        String record = Contracts.JSON.createObjectNode().put("v", 1).put("sub", user.sub).put("kind", "active")
                .put("id", "an-older-registration").put("seed", Base64.getEncoder().encodeToString(user.seed)).toString();
        String encrypted = Contracts.JSON.readTree(env.bao("POST", "transit/encrypt/mcp-authenticators",
                Contracts.JSON.createObjectNode().put("plaintext", Base64.getEncoder().encodeToString(record.getBytes())).toString()).body())
                .path("data").path("ciphertext").stringValue();
        env.bao("POST", "secret/data/mcp/authenticators/" + SecretKey.hashOf(user.sub),
                Contracts.JSON.createObjectNode().set("data", Contracts.JSON.createObjectNode().put("ciphertext", encrypted)).toString());

        assertThat(verify(user.sub, nextCode(user.seed)).status()).isEqualTo(503);
        // Not dropped: the seed exists, it only is not this registration's.
        assertThat(gatewayStatus(user.sub).json().path("state").stringValue()).isEqualTo("active");
    }

    @Test
    void registrationChangesDuringParallelVerificationNeverGiveAnUnexpectedAnswer() throws Exception {
        Registered user = register("ursula");
        String bffToken = tokens.bffUser(user.sub, "ursula");
        String wrong = wrongCode(user.seed);
        java.util.concurrent.atomic.AtomicBoolean done = new java.util.concurrent.atomic.AtomicBoolean();
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Future<List<Integer>>> readers = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                readers.add(pool.submit(() -> {
                    List<Integer> statuses = new ArrayList<>();
                    while (!done.get()) {
                        BrokerClient.Response response = verify(user.sub, wrong);
                        statuses.add(response.status());
                        if (response.status() == 200) {
                            assertThat(response.json().path("result").stringValue())
                                    .isIn("invalid", "locked", "disabled", "not_registered");
                        }
                    }
                    return statuses;
                }));
            }
            for (int i = 0; i < 4; i++) {
                assertThat(bff.send("DELETE", "/v1/authenticator", bffToken, null, null).status()).isEqualTo(204);
                Enrolled enrolled = startOnly(bffToken);
                assertThat(confirm(bffToken, enrolled.id, currentCode(enrolled.seed)).status()).isEqualTo(200);
            }
            done.set(true);
            for (Future<List<Integer>> reader : readers) {
                assertThat(reader.get()).isNotEmpty().allMatch(status -> status == 200 || status == 503);
            }
        } finally {
            done.set(true);
            pool.shutdownNow();
        }
        assertThat(gatewayStatus(user.sub).json().path("state").stringValue()).isEqualTo("active");
    }

    @Test
    void startsAreLimitedWithARetryAfter() {
        String bffToken = tokens.bffUser(newSub(), "victor");
        for (int i = 0; i < 10; i++) {
            SEEDS.add(bff.send("POST", "/v1/authenticator/enrollment", bffToken, null, null).json().path("secret").stringValue());
        }
        BrokerClient.Response limited = bff.send("POST", "/v1/authenticator/enrollment", bffToken, null, null);
        assertThat(limited.status()).isEqualTo(429);
        assertThat(Long.parseLong(limited.header("Retry-After"))).isBetween(3500L, 3600L);
    }

    @Test
    void anEmptyRemovalOrResetLeavesNoAuditLine(CapturedOutput output) {
        String sub = newSub();
        String removeId = TestTokens.newRequestId();
        assertThat(bff.send("DELETE", "/v1/authenticator", tokens.bffUser(sub, "walt"), removeId, null).status()).isEqualTo(204);
        String resetId = TestTokens.newRequestId();
        assertThat(offboarding.send("POST", "/v1/admin/users/" + sub + "/authenticator/reset", null, resetId, null).status())
                .isEqualTo(204);
        assertThat(auditEvents(output, removeId)).isEmpty();
        assertThat(auditEvents(output, resetId)).isEmpty();
    }

    // Who may call what ----------------------------------------------------------------------------------

    @Test
    void callersAreLimitedToTheirOwnOperations() {
        Registered user = register("olivia");
        String bffToken = tokens.bffUser(user.sub, "olivia");
        String code = "{\"code\":\"123456\"}";

        assertThat(bff.send("POST", "/v1/authenticator/verify", bffToken, null, code).status()).isEqualTo(403);
        assertThat(bff.send("POST", "/v1/authenticator/invalidate-codes", bffToken, null, null).status()).isEqualTo(403);
        assertThat(gw("POST", "/v1/authenticator/enrollment", user.sub, null).status()).isEqualTo(403);
        assertThat(gw("POST", "/v1/authenticator/enrollment/confirm", user.sub, "{\"enrollmentId\":\"enr_aaaaaaaaaaaaaaaaaaaaaa\",\"code\":\"123456\"}").status()).isEqualTo(403);
        assertThat(gw("DELETE", "/v1/authenticator", user.sub, null).status()).isEqualTo(403);
        assertThat(gw("POST", "/v1/admin/users/" + user.sub + "/authenticator/reset", user.sub, null).status()).isEqualTo(403);
        assertThat(bff.send("POST", "/v1/admin/users/" + user.sub + "/authenticator/reset", bffToken, null, null).status())
                .isEqualTo(403);
        assertThat(offboarding.send("POST", "/v1/authenticator/verify", null, null, code).status()).isEqualTo(403);
        assertThat(offboarding.send("GET", "/v1/authenticator", null, null, null).status()).isEqualTo(403);

        // Gateway tokens without the tool, the service variant, a BFF token with the wrong audience.
        String rid = TestTokens.newRequestId();
        String noTool = tokens.gatewayUser(user.sub, "olivia", rid, null);
        assertThat(gateway.send("POST", "/v1/authenticator/verify", noTool, rid, code).status()).isEqualTo(401);
        assertThat(gateway.send("GET", "/v1/authenticator", noTool, rid, null).status()).isEqualTo(401);
        assertThat(gateway.send("POST", "/v1/authenticator/verify", tokens.gatewayService(rid), rid, code).status()).isEqualTo(401);
        assertThat(bff.send("GET", "/v1/authenticator", tokens.bff(user.sub, "olivia", "mcp-portal-bff", "someone-else"), null, null)
                .status()).isEqualTo(401);
        assertThat(bff.send("GET", "/v1/authenticator", null, null, null).status()).isEqualTo(401);
        assertThat(gatewayStatus(user.sub).status()).isEqualTo(200);
    }

    @Test
    void theUserIsAlwaysTheTokensSub() {
        Registered alice = register("peggy");
        Registered bob = register("quentin");
        String burnForAlice = TestTokens.newRequestId();
        assertThat(gateway.send("POST", "/v1/authenticator/invalidate-codes",
                tokens.gatewayUser(alice.sub, "peggy", burnForAlice, TOOL), burnForAlice, null).status()).isEqualTo(204);
        assertThat(verify(bob.sub, nextCode(bob.seed)).json().path("result").stringValue()).isEqualTo("ok");
        assertThat(verify(alice.sub, nextCode(alice.seed)).json().path("result").stringValue()).isEqualTo("burned");

        assertThat(bff.send("DELETE", "/v1/authenticator", tokens.bffUser(bob.sub, "quentin"), null, null).status()).isEqualTo(204);
        assertThat(gatewayStatus(alice.sub).json().path("state").stringValue()).isEqualTo("active");
        assertThat(gatewayStatus(bob.sub).json().path("state").stringValue()).isEqualTo("none");
    }

    // Helpers --------------------------------------------------------------------------------------------

    record Enrolled(String id, byte[] seed) {
    }

    record Registered(String sub, byte[] seed) {
    }

    private Enrolled startOnly(String bffToken) {
        BrokerClient.Response started = bff.send("POST", "/v1/authenticator/enrollment", bffToken, null, null);
        assertThat(started.status()).isEqualTo(201);
        String secret = started.json().path("secret").stringValue();
        SEEDS.add(secret);
        return new Enrolled(started.json().path("enrollmentId").stringValue(), Base32.decode(secret));
    }

    private Registered register(String username) {
        String sub = newSub();
        String bffToken = tokens.bffUser(sub, username);
        Enrolled enrolled = startOnly(bffToken);
        assertThat(confirm(bffToken, enrolled.id, currentCode(enrolled.seed)).status()).isEqualTo(200);
        return new Registered(sub, enrolled.seed);
    }

    private BrokerClient.Response confirm(String bffToken, String enrollmentId, String code) {
        return bff.send("POST", "/v1/authenticator/enrollment/confirm", bffToken, null,
                "{\"enrollmentId\":\"" + enrollmentId + "\",\"code\":\"" + code + "\"}");
    }

    private BrokerClient.Response verify(String sub, String code) {
        return gw("POST", "/v1/authenticator/verify", sub, "{\"code\":\"" + code + "\"}");
    }

    private BrokerClient.Response gatewayStatus(String sub) {
        return gw("GET", "/v1/authenticator", sub, null);
    }

    /** The internal JWT binds the request id (rid), so token and X-Request-Id are made together. */
    private BrokerClient.Response gw(String method, String path, String sub, String body) {
        String requestId = TestTokens.newRequestId();
        return gateway.send(method, path, tokens.gatewayUser(sub, "test-user", requestId, TOOL), requestId, body);
    }

    private static String currentCode(byte[] seed) {
        return Totp.code(seed, Totp.stepOf(Instant.now()));
    }

    /** The code of the step after the current one: inside the window, and newer than the one that activated the registration. */
    private static String nextCode(byte[] seed) {
        return Totp.code(seed, Totp.stepOf(Instant.now()) + 1);
    }

    /** A six digit code that is none of the codes the window accepts, so a test never hits a valid one by chance. */
    private static String wrongCode(byte[] seed) {
        long step = Totp.stepOf(Instant.now());
        List<String> valid = List.of(Totp.code(seed, step - 2), Totp.code(seed, step - 1), Totp.code(seed, step),
                Totp.code(seed, step + 1), Totp.code(seed, step + 2));
        for (int candidate = 100000; ; candidate++) {
            String code = String.valueOf(candidate);
            if (!valid.contains(code)) {
                return code;
            }
        }
    }

    private static long count(List<String> results, String value) {
        return results.stream().filter(value::equals).count();
    }

    private static List<String> parallel(int requests, Callable<String> call) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(requests);
        try {
            CountDownLatch go = new CountDownLatch(1);
            List<Future<String>> futures = new ArrayList<>();
            for (int i = 0; i < requests; i++) {
                futures.add(pool.submit(() -> {
                    go.await();
                    return call.call();
                }));
            }
            go.countDown();
            List<String> results = new ArrayList<>();
            for (Future<String> future : futures) {
                results.add(future.get());
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private static String newSub() {
        return "auth-it-" + UUID.randomUUID();
    }

    private static List<JsonNode> auditEvents(CapturedOutput output, String requestId) {
        List<JsonNode> events = output.getAll().lines()
                .filter(line -> line.startsWith("{") && line.contains("\"component\":\"broker\""))
                .map(line -> Contracts.JSON.readTree(line))
                .filter(event -> requestId.equals(event.path("requestId").stringValue()))
                .collect(Collectors.toList());
        for (JsonNode event : events) {
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).as(event.toString()).isEmpty();
        }
        return events;
    }
}
