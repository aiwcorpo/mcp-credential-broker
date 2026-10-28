package pl.aiwcorpo.mcp.broker.authenticator;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.InternalJwtClaims;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.MutableClock;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import tools.jackson.databind.JsonNode;

/**
 * test-vectors/totp/ of mcp-contracts run against the real service, PostgreSQL and OpenBao Transit, with the clock
 * set to the {@code at} of each step. The reference behaviour is scripts/lib/totp.mjs of mcp-contracts.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class TotpVectorTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final MutableClock CLOCK = new MutableClock(Instant.parse("2026-10-14T17:00:00Z"));

    @TestConfiguration
    static class ClockConfiguration {

        @Bean
        @Primary
        MutableClock vectorClock() {
            return CLOCK;
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @Autowired
    AuthenticatorService service;

    @Autowired
    AuthenticatorSeedStore seeds;

    @Autowired
    JdbcClient jdbc;

    static Stream<Arguments> vectors() {
        List<Resource> files = Contracts.vectors("totp");
        assertThat(files).hasSizeGreaterThanOrEqualTo(45);
        return files.stream()
                .filter(file -> Contracts.json("test-vectors/totp/" + file.getFilename()).has("steps"))
                .map(file -> Arguments.of(file.getFilename(), Contracts.json("test-vectors/totp/" + file.getFilename())));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void vector(String name, JsonNode vector) {
        String sub = "totp-vector-" + UUID.randomUUID();
        byte[] seed = Base32.decode(vector.path("secret").stringValue());
        setUp(sub, seed, vector);

        int index = 0;
        for (JsonNode step : vector.path("steps")) {
            index++;
            CLOCK.set(Instant.parse(step.path("at").stringValue()));
            JsonNode expected = step.path("expected");
            String label = name + " step " + index + " (" + step.path("op").stringValue() + " at " + step.path("at").stringValue() + ")";
            switch (step.path("op").stringValue()) {
                case "verify" -> {
                    String code = step.path("code").stringValue();
                    if (!code.matches("^[0-9]{6}$")) {
                        assertThat(expected.path("result").stringValue()).as(label).isEqualTo("malformed");
                        break;
                    }
                    AuthenticatorService.Verified verified = service.verify(gateway(sub), code);
                    assertThat(verified.result().wire()).as(label).isEqualTo(expected.path("result").stringValue());
                    if (expected.has("retryAfterSeconds")) {
                        assertThat(verified.retryAfterSeconds()).as(label).isEqualTo(expected.path("retryAfterSeconds").asLong());
                    }
                }
                case "burn" -> service.invalidateCodes(gateway(sub));
                case "confirm" -> {
                    String code = step.path("code").stringValue();
                    String result;
                    if (!code.matches("^[0-9]{6}$")) {
                        result = "malformed";
                    } else {
                        try {
                            service.confirmEnrollment(portalUser(sub), PENDING_ID, code);
                            result = "active";
                        } catch (AuthenticatorRefusedException e) {
                            result = e.error();
                        }
                    }
                    assertThat(result).as(label).isEqualTo(expected.path("result").stringValue());
                }
                default -> throw new IllegalStateException("unknown op " + step.path("op").stringValue());
            }
            if (expected.has("lastAcceptedStep") && !expected.has("after")) {
                assertThat(row(sub).get("last_accepted_step")).as(label).isEqualTo(expected.path("lastAcceptedStep").asLong());
            }
            JsonNode after = expected.path("after");
            if (after.has("lastAcceptedStep")) {
                Object stored = row(sub).get("last_accepted_step");
                assertThat(stored).as(label + " lastAcceptedStep")
                        .isEqualTo(after.path("lastAcceptedStep").isNull() ? null : after.path("lastAcceptedStep").asLong());
            }
            if (after.has("lockedUntil")) {
                Object stored = row(sub).get("locked_until");
                assertThat(stored == null ? null : ((Timestamp) stored).toInstant().toString()).as(label + " lockedUntil")
                        .isEqualTo(after.path("lockedUntil").isNull() ? null : after.path("lockedUntil").stringValue());
            }
            if (after.has("disabled")) {
                assertThat("disabled".equals(row(sub).get("state"))).as(label + " disabled")
                        .isEqualTo(after.path("disabled").asBoolean());
            }
        }
    }

    @Test
    void theRfc6238CodesAreComputed() {
        JsonNode vector = Contracts.json("test-vectors/totp/rfc6238-sha1.json");
        byte[] seed = Base32.decode(vector.path("secret").stringValue());
        for (JsonNode c : vector.path("cases")) {
            assertThat(Totp.stepOf(Instant.ofEpochSecond(c.path("time").asLong()))).isEqualTo(c.path("step").asLong());
            assertThat(Totp.code(seed, c.path("step").asLong())).isEqualTo(c.path("code").stringValue());
        }
    }

    @Test
    void theOtpauthUriHasTheFixedForm() {
        JsonNode vector = Contracts.json("test-vectors/totp/otpauth-uri.json");
        for (JsonNode c : vector.path("cases")) {
            assertThat(AuthenticatorService.otpauthUri(c.path("username").stringValue(), vector.path("secret").stringValue()))
                    .isEqualTo(c.path("uri").stringValue());
        }
        assertThat(Base32.encode(Base32.decode(vector.path("secret").stringValue()))).isEqualTo(vector.path("secret").stringValue());
        for (JsonNode invalid : vector.path("invalidSecrets")) {
            assertThat(invalid.stringValue()).doesNotMatch("^[A-Z2-7]{32}$");
        }
    }

    @Test
    void unconfirmedEnrollmentsAreSweptAfterTheirTtl() {
        String stale = "totp-sweep-" + UUID.randomUUID();
        String fresh = "totp-sweep-" + UUID.randomUUID();
        CLOCK.set(Instant.parse("2026-10-20T10:00:00Z"));
        for (String sub : List.of(stale, fresh)) {
            jdbc.sql("insert into authenticator (sub, state, updated_at, pending_id, pending_created_at) "
                            + "values (:sub, 'none', :now, :id, :created)")
                    .param("sub", sub).param("now", Timestamp.from(CLOCK.instant())).param("id", PENDING_ID)
                    .param("created", Timestamp.from(sub.equals(stale) ? CLOCK.instant().minusSeconds(601) : CLOCK.instant().minusSeconds(599)))
                    .update();
            seeds.putPending(sub, PENDING_ID, new byte[20]);
        }

        assertThat(service.sweepExpiredEnrollments()).isEqualTo(1);
        assertThat(seeds.getPending(stale)).isEmpty();
        assertThat(row(stale).get("pending_id")).isNull();
        assertThat(seeds.getPending(fresh)).isPresent();
        assertThat(row(fresh).get("pending_id")).isEqualTo(PENDING_ID);
        assertThat(service.sweepExpiredEnrollments()).isZero();
    }

    private static final String PENDING_ID = "enr_vector0123456789";

    private void setUp(String sub, byte[] seed, JsonNode vector) {
        Instant created = Instant.parse("2026-10-01T00:00:00Z");
        jdbc.sql("insert into authenticator (sub, state, updated_at) values (:sub, 'none', :now)")
                .param("sub", sub).param("now", Timestamp.from(created)).update();
        JsonNode initial = vector.path("initial");
        if (!initial.isMissingNode()) {
            boolean disabled = initial.path("disabled").asBoolean(false);
            String registrationId = "vector-registration-" + UUID.randomUUID().toString().substring(0, 8);
            jdbc.sql("""
                    update authenticator set state = :state, registration_id = :rid, registered_at = :created,
                        last_accepted_step = :step, locked_until = :locked, disabled_at = :disabledAt where sub = :sub
                    """)
                    .param("state", disabled ? "disabled" : "active")
                    .param("rid", registrationId)
                    .param("created", Timestamp.from(created))
                    .param("step", initial.path("lastAcceptedStep").isNull() ? null : initial.path("lastAcceptedStep").asLong())
                    .param("locked", initial.path("lockedUntil").isNull() ? null
                            : Timestamp.from(Instant.parse(initial.path("lockedUntil").stringValue())))
                    .param("disabledAt", disabled ? Timestamp.from(created) : null)
                    .param("sub", sub)
                    .update();
            for (JsonNode at : initial.path("failures")) {
                failure(sub, at.stringValue(), true);
            }
            for (JsonNode at : initial.path("dailyFailures")) {
                failure(sub, at.stringValue(), false);
            }
            seeds.putActive(sub, registrationId, seed);
        }
        JsonNode enrollment = vector.path("enrollment");
        if (!enrollment.isMissingNode()) {
            jdbc.sql("update authenticator set pending_id = :id, pending_created_at = :created, pending_wrong_codes = :wrong where sub = :sub")
                    .param("id", PENDING_ID)
                    .param("created", Timestamp.from(Instant.parse(enrollment.path("createdAt").stringValue())))
                    .param("wrong", enrollment.path("wrongCodes").asInt())
                    .param("sub", sub)
                    .update();
            seeds.putPending(sub, PENDING_ID, seed);
        }
    }

    private void failure(String sub, String at, boolean inShortWindow) {
        jdbc.sql("insert into authenticator_failure (sub, at, in_short_window) values (:sub, :at, :short)")
                .param("sub", sub).param("at", Timestamp.from(Instant.parse(at))).param("short", inShortWindow).update();
    }

    private Map<String, Object> row(String sub) {
        return jdbc.sql("select * from authenticator where sub = :sub").param("sub", sub).query().singleRow();
    }

    private static Caller.Gateway gateway(String sub) {
        return new Caller.Gateway("0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f", new InternalJwtClaims(sub, "vector-user", List.of(),
                "claude-code", "delete_issue", null, "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f", "20261026120000-a1b2c3d",
                UUID.randomUUID().toString(), false));
    }

    private static Caller.PortalUser portalUser(String sub) {
        return new Caller.PortalUser("0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f", sub, "vector-user", "mcp-portal-bff", Map.of());
    }
}
