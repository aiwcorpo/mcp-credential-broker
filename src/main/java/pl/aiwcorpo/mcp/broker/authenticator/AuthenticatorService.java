package pl.aiwcorpo.mcp.broker.authenticator;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.OptionalLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.InternalJwtClaims;
import pl.aiwcorpo.mcp.broker.authenticator.AuthenticatorRecord.State;
import pl.aiwcorpo.mcp.broker.authenticator.AuthenticatorSeedStore.Seed;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;

/**
 * The TOTP authenticator of C4 (CC-091, CC-092, CC-126, CC-128). Every change of a user's counters, lock or
 * registration runs in one transaction that holds the row lock of that user's {@code authenticator} row, so the
 * check "not locked, not disabled", the 5-in-15-minutes and 20-in-24-hours counters and the lock are one atomic step
 * per {@code sub}. The seed is read from OpenBao before the lock is taken and compared by registration id inside
 * it, so the lock is never held across a call that can be slow for a user who is not allowed to try anyway.
 */
public class AuthenticatorService {

    /** How many times verify re-reads when a registration was replaced between reading the seed and taking the lock. */
    private static final int MAX_ATTEMPTS = 3;
    private static final int SWEEP_BATCH = 100;
    private static final Logger log = LoggerFactory.getLogger(AuthenticatorService.class);

    public enum VerifyResult {
        OK, INVALID, REPLAYED, BURNED, LOCKED, DISABLED, NOT_REGISTERED;

        public String wire() {
            return name().toLowerCase(java.util.Locale.ROOT);
        }
    }

    /** {@code retryAfterSeconds} is set exactly with {@link VerifyResult#LOCKED}; {@code disabledNow} marks the failure that switched the authenticator off. */
    public record Verified(VerifyResult result, Long retryAfterSeconds, boolean disabledNow) {
    }

    public record Status(String state, Instant registeredAt, Instant lastUsedAt, Instant lockedUntil, Instant disabledAt) {
    }

    /** The only value that carries a seed out of the broker; never log it. */
    public record Enrollment(String enrollmentId, String otpauthUri, String secret, Instant expiresAt) {

        @Override
        public String toString() {
            return "Enrollment[enrollmentId=" + enrollmentId + "]";
        }
    }

    private sealed interface ConfirmOutcome {
        record Active(Status status) implements ConfirmOutcome {
        }

        record WrongCode() implements ConfirmOutcome {
        }

        record Invalid() implements ConfirmOutcome {
        }
    }

    private final AuthenticatorRepository repository;
    private final AuthenticatorSeedStore seeds;
    private final AuditLog audit;
    private final Clock clock;
    private final TransactionTemplate tx;
    private final BrokerProperties.Authenticator config;
    private final SecureRandom random = new SecureRandom();

    public static AuthenticatorService create(JdbcClient jdbc, AuthenticatorSeedStore seeds, AuditLog audit, Clock clock,
            TransactionTemplate tx, BrokerProperties.Authenticator config) {
        return new AuthenticatorService(new AuthenticatorRepository(jdbc), seeds, audit, clock, tx, config);
    }

    AuthenticatorService(AuthenticatorRepository repository, AuthenticatorSeedStore seeds, AuditLog audit, Clock clock,
            TransactionTemplate tx, BrokerProperties.Authenticator config) {
        this.repository = repository;
        this.seeds = seeds;
        this.audit = audit;
        this.clock = clock;
        this.tx = tx;
        this.config = config;
    }

    public Status status(String sub) {
        Instant now = clock.instant();
        return repository.find(sub).map(row -> statusOf(row, now)).orElseGet(() -> new Status("none", null, null, null, null));
    }

    // Registration (BFF) ---------------------------------------------------------------------------------

    public Enrollment startEnrollment(Caller.PortalUser user) {
        AuditLog.Entry entry = audit.event("authenticator", user.requestId()).user(user.sub(), user.username(), user.azp());
        try {
            Enrollment enrollment = tx.execute(status -> startEnrollmentLocked(user));
            entry.ok("authenticator_enrollment_started");
            return enrollment;
        } catch (AuthenticatorRefusedException e) {
            entry.denied("authenticator_enrollment_failed", "rate_limited".equals(e.error()) ? "rate_limited" : null);
            throw e;
        } catch (RuntimeException e) {
            throw failed(entry, e);
        }
    }

    private Enrollment startEnrollmentLocked(Caller.PortalUser user) {
        Instant now = clock.instant();
        AuthenticatorRecord row = repository.lockOrCreate(user.sub(), now);
        if (row.state == State.ACTIVE) {
            throw new AuthenticatorRefusedException(409, "already_registered");
        }
        if (row.enrollWindowStart == null || !now.isBefore(row.enrollWindowStart.plus(Duration.ofHours(1)))) {
            row.enrollWindowStart = now;
            row.enrollStarts = 0;
        }
        if (row.enrollStarts >= config.enrollmentStartsPerHour()) {
            throw new AuthenticatorRefusedException(429, "rate_limited");
        }
        row.enrollStarts++;

        byte[] seed = new byte[20];
        random.nextBytes(seed);
        String enrollmentId = "enr_" + randomToken(16);
        seeds.putPending(user.sub(), enrollmentId, seed);
        row.pendingId = enrollmentId;
        row.pendingCreatedAt = now;
        row.pendingWrongCodes = 0;
        repository.save(row, now);

        String secret = Base32.encode(seed);
        java.util.Arrays.fill(seed, (byte) 0);
        return new Enrollment(enrollmentId, otpauthUri(user.username(), secret), secret, now.plus(config.enrollmentTtl()));
    }

    public Status confirmEnrollment(Caller.PortalUser user, String enrollmentId, String code) {
        AuditLog.Entry entry = audit.event("authenticator", user.requestId()).user(user.sub(), user.username(), user.azp());
        try {
            ConfirmOutcome outcome = confirm(user.sub(), enrollmentId, code);
            switch (outcome) {
                case ConfirmOutcome.Active active -> {
                    entry.ok("authenticator_registered");
                    return active.status();
                }
                case ConfirmOutcome.WrongCode wrong -> {
                    entry.denied("authenticator_enrollment_failed", null);
                    throw new AuthenticatorRefusedException(422, "invalid_code");
                }
                case ConfirmOutcome.Invalid invalid -> {
                    entry.denied("authenticator_enrollment_failed", null);
                    throw new AuthenticatorRefusedException(422, "enrollment_invalid");
                }
            }
        } catch (AuthenticatorRefusedException e) {
            throw e;
        } catch (RuntimeException e) {
            throw failed(entry, e);
        }
    }

    private ConfirmOutcome confirm(String sub, String enrollmentId, String code) {
        AuthenticatorRecord peek = repository.find(sub).orElse(null);
        if (peek == null || peek.pendingId == null || !peek.pendingId.equals(enrollmentId)) {
            return new ConfirmOutcome.Invalid();
        }
        Seed pending = seeds.getPending(sub).orElse(null);
        try {
            return tx.execute(status -> confirmLocked(sub, enrollmentId, code, pending));
        } finally {
            if (pending != null) {
                java.util.Arrays.fill(pending.bytes(), (byte) 0);
            }
        }
    }

    private ConfirmOutcome confirmLocked(String sub, String enrollmentId, String code, Seed pending) {
        Instant now = clock.instant();
        AuthenticatorRecord row = repository.lock(sub).orElse(null);
        if (row == null || row.pendingId == null || !row.pendingId.equals(enrollmentId)) {
            return new ConfirmOutcome.Invalid();
        }
        boolean expired = now.isAfter(row.pendingCreatedAt.plus(config.enrollmentTtl()));
        if (expired || pending == null || !pending.id().equals(enrollmentId)) {
            destroyPending(row, now);
            return new ConfirmOutcome.Invalid();
        }
        OptionalLong step = Totp.matchingStep(pending.bytes(), code, now, config.windowSteps());
        if (step.isEmpty()) {
            row.pendingWrongCodes++;
            if (row.pendingWrongCodes >= config.enrollmentMaxWrongCodes()) {
                destroyPending(row, now);
                return new ConfirmOutcome.Invalid();
            }
            repository.save(row, now);
            return new ConfirmOutcome.WrongCode();
        }
        String registrationId = randomHex(16);
        seeds.putActive(sub, registrationId, pending.bytes());
        seeds.deletePending(sub);
        row.state = State.ACTIVE;
        row.registrationId = registrationId;
        row.registeredAt = now;
        row.lastUsedAt = null;
        row.lastAcceptedStep = step.getAsLong();
        row.burnedThrough = null;
        row.disabledAt = null;
        row.clearPending();
        repository.deleteFailures(sub);
        repository.save(row, now);
        return new ConfirmOutcome.Active(statusOf(row, now));
    }

    private void destroyPending(AuthenticatorRecord row, Instant now) {
        seeds.deletePending(row.sub);
        row.clearPending();
        repository.save(row, now);
    }

    /**
     * Deletes the seeds of enrollments that were never confirmed (CC-092: a pending seed does not outlive its 10
     * minutes). Without it an abandoned enrollment would keep its ciphertext in OpenBao until the user came back.
     *
     * @return how many enrollments were destroyed
     */
    public int sweepExpiredEnrollments() {
        Instant cutoff = clock.instant().minus(config.enrollmentTtl());
        int destroyed = 0;
        for (String sub : repository.findPendingBefore(cutoff, SWEEP_BATCH)) {
            Boolean done = tx.execute(status -> {
                Instant now = clock.instant();
                AuthenticatorRecord row = repository.lock(sub).orElse(null);
                if (row == null || row.pendingId == null || !now.isAfter(row.pendingCreatedAt.plus(config.enrollmentTtl()))) {
                    return false;
                }
                destroyPending(row, now);
                return true;
            });
            if (Boolean.TRUE.equals(done)) {
                destroyed++;
            }
        }
        return destroyed;
    }

    /** Removal by the owner after a fresh MFA (BFF). Idempotent; a lock of the user stays (CC-091). */
    public void remove(Caller.PortalUser user) {
        AuditLog.Entry entry = audit.event("authenticator", user.requestId()).user(user.sub(), user.username(), user.azp());
        try {
            tx.executeWithoutResult(status -> removeLocked(user.sub()));
            entry.ok("authenticator_removed");
        } catch (RuntimeException e) {
            throw failed(entry, e);
        }
    }

    /** Reset by helpdesk (mTLS CN mcp-offboarding); {@code sub} is the target user. */
    public void reset(String requestId, String sub) {
        AuditLog.Entry entry = audit.event("authenticator", requestId).user(sub, null, null);
        try {
            tx.executeWithoutResult(status -> removeLocked(sub));
            entry.ok("authenticator_reset_by_admin");
        } catch (RuntimeException e) {
            throw failed(entry, e);
        }
    }

    private void removeLocked(String sub) {
        AuthenticatorRecord row = repository.lock(sub).orElse(null);
        if (row == null) {
            return;
        }
        seeds.deleteActive(sub);
        seeds.deletePending(sub);
        row.clearRegistration();
        row.clearPending();
        repository.save(row, clock.instant());
    }

    // Verification (gateway) -----------------------------------------------------------------------------

    public Verified verify(Caller.Gateway caller, String code) {
        InternalJwtClaims claims = caller.claims();
        AuditLog.Entry entry = gatewayEntry(caller);
        Verified verified;
        try {
            verified = verifyAtomically(claims.sub(), code);
        } catch (RuntimeException e) {
            throw failed(entry, e);
        }
        switch (verified.result()) {
            case OK -> entry.decision("allow").ok("totp_verified");
            case INVALID -> entry.decision("deny").denied("totp_invalid", null);
            case REPLAYED -> entry.decision("deny").denied("totp_replayed", null);
            case BURNED -> entry.decision("deny").denied("totp_burned", null);
            case LOCKED -> entry.decision("deny").denied("totp_locked", "rate_limited");
            case DISABLED -> entry.decision("deny").denied("totp_disabled", null);
            case NOT_REGISTERED -> entry.decision("deny").denied("totp_not_registered", null);
        }
        if (verified.disabledNow()) {
            gatewayEntry(caller).decision("deny").denied("authenticator_disabled", null);
        }
        return verified;
    }

    private Verified verifyAtomically(String sub, String code) {
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            Instant now = clock.instant();
            AuthenticatorRecord peek = repository.find(sub).orElse(null);
            if (peek == null || peek.state == State.NONE) {
                return new Verified(VerifyResult.NOT_REGISTERED, null, false);
            }
            if (peek.state == State.DISABLED) {
                return new Verified(VerifyResult.DISABLED, null, false);
            }
            if (peek.lockedAt(now)) {
                return locked(peek, now);
            }
            Seed seed = seeds.getActive(sub).orElse(null);
            try {
                Verified verified = tx.execute(status -> verifyLocked(sub, code, seed));
                if (verified != null) {
                    return verified;
                }
            } finally {
                if (seed != null) {
                    java.util.Arrays.fill(seed.bytes(), (byte) 0);
                }
            }
        }
        throw new SecretStoreUnavailableException("authenticator registration changed repeatedly during verification");
    }

    /** Null when the seed read earlier is not the one of the registration now under lock; the caller re-reads. */
    private Verified verifyLocked(String sub, String code, Seed seed) {
        Instant now = clock.instant();
        AuthenticatorRecord row = repository.lock(sub).orElse(null);
        if (row == null || row.state == State.NONE) {
            return new Verified(VerifyResult.NOT_REGISTERED, null, false);
        }
        if (row.state == State.DISABLED) {
            return new Verified(VerifyResult.DISABLED, null, false);
        }
        if (seed == null || !seed.id().equals(row.registrationId)) {
            return null;
        }
        if (row.lockedAt(now)) {
            return locked(row, now);
        }
        if (row.lockedUntil != null) {
            row.lockedUntil = null;
            repository.clearShortWindow(sub);
        }
        OptionalLong step = Totp.matchingStep(seed.bytes(), code, now, config.windowSteps());
        // A burned step is not a wrong guess (CC-128): it must not count, or a held code could lock the owner out.
        if (step.isPresent() && row.burnedThrough != null && step.getAsLong() <= row.burnedThrough) {
            repository.save(row, now);
            return new Verified(VerifyResult.BURNED, null, false);
        }
        if (step.isPresent() && (row.lastAcceptedStep == null || step.getAsLong() > row.lastAcceptedStep)) {
            row.lastAcceptedStep = step.getAsLong();
            row.lastUsedAt = now;
            repository.clearShortWindow(sub);
            repository.save(row, now);
            return new Verified(VerifyResult.OK, null, false);
        }
        boolean disabledNow = recordFailure(row, now);
        repository.save(row, now);
        return new Verified(step.isEmpty() ? VerifyResult.INVALID : VerifyResult.REPLAYED, null, disabledNow);
    }

    private boolean recordFailure(AuthenticatorRecord row, Instant now) {
        repository.deleteFailuresBefore(row.sub, now.minus(config.dailyWindow()));
        repository.addFailure(row.sub, now);
        if (repository.countFailures(row.sub, now.minus(config.failureWindow()), true) >= config.maxFailures()) {
            row.lockedUntil = now.plus(config.lockDuration());
        }
        if (repository.countFailures(row.sub, now.minus(config.dailyWindow()), false) >= config.dailyFailureLimit()) {
            row.state = State.DISABLED;
            row.disabledAt = now;
            return true;
        }
        return false;
    }

    private static Verified locked(AuthenticatorRecord row, Instant now) {
        long seconds = Math.max(1, (long) Math.ceil(Duration.between(now, row.lockedUntil).toMillis() / 1000.0));
        return new Verified(VerifyResult.LOCKED, seconds, false);
    }

    /** CC-128: the step of the broker clock and the next one count as used. Idempotent, never lowers a step. */
    public void invalidateCodes(Caller.Gateway caller) {
        AuditLog.Entry entry = gatewayEntry(caller);
        try {
            boolean burned = Boolean.TRUE.equals(tx.execute(status -> burnLocked(caller.claims().sub())));
            if (burned) {
                entry.ok("totp_steps_burned");
            }
        } catch (RuntimeException e) {
            throw failed(entry, e);
        }
    }

    private boolean burnLocked(String sub) {
        Instant now = clock.instant();
        AuthenticatorRecord row = repository.lock(sub).orElse(null);
        if (row == null || row.state != State.ACTIVE) {
            return false;
        }
        long through = Math.max(row.burnedThrough == null ? -1 : row.burnedThrough, Totp.stepOf(now) + 1);
        row.burnedThrough = through;
        row.lastAcceptedStep = Math.max(row.lastAcceptedStep == null ? -1 : row.lastAcceptedStep, through);
        repository.save(row, now);
        return true;
    }

    // Helpers --------------------------------------------------------------------------------------------

    private AuditLog.Entry gatewayEntry(Caller.Gateway caller) {
        InternalJwtClaims claims = caller.claims();
        return audit.event("authenticator", caller.requestId())
                .user(claims.sub(), claims.usr(), claims.azp())
                .gatewayContext(claims.vs(), claims.tool(), claims.prv());
    }

    private RuntimeException failed(AuditLog.Entry entry, RuntimeException e) {
        if (e instanceof SecretStoreUnavailableException) {
            entry.error("secret_store_unavailable", "upstream_unavailable");
        } else {
            log.warn("Authenticator operation failed: {}", e.getClass().getSimpleName());
            entry.error("internal_error", "upstream_unavailable");
        }
        return e;
    }

    private static Status statusOf(AuthenticatorRecord row, Instant now) {
        Instant lockedUntil = row.lockedAt(now) ? row.lockedUntil : null;
        return switch (row.state) {
            case NONE -> new Status("none", null, null, lockedUntil, null);
            case ACTIVE -> new Status("active", row.registeredAt, row.lastUsedAt, lockedUntil, null);
            case DISABLED -> new Status("disabled", row.registeredAt, row.lastUsedAt, lockedUntil, row.disabledAt);
        };
    }

    static String otpauthUri(String username, String secretBase32) {
        return "otpauth://totp/MCP%20Platform:" + encodeUriComponent(username == null || username.isBlank() ? "user" : username)
                + "?secret=" + secretBase32 + "&issuer=MCP%20Platform&algorithm=SHA1&digits=6&period=30";
    }

    /** Same unreserved set as JavaScript's encodeURIComponent, which the contract's reference uses. */
    private static String encodeUriComponent(String value) {
        StringBuilder out = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xff);
            if (c < 0x80 && (Character.isLetterOrDigit(c) || "-_.!~*'()".indexOf(c) >= 0)) {
                out.append(c);
            } else {
                out.append('%').append(String.format("%02X", b & 0xff));
            }
        }
        return out.toString();
    }

    private String randomToken(int bytes) {
        byte[] raw = new byte[bytes];
        random.nextBytes(raw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    private String randomHex(int bytes) {
        byte[] raw = new byte[bytes];
        random.nextBytes(raw);
        return HexFormat.of().formatHex(raw);
    }
}
