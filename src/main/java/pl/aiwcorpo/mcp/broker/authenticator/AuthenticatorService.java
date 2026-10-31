package pl.aiwcorpo.mcp.broker.authenticator;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
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
import pl.aiwcorpo.mcp.broker.credential.CredentialService;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;

/**
 * The TOTP authenticator of C4 (CC-091, CC-092, CC-126, CC-128). Every change of a user's counters, lock or
 * registration runs in one transaction that holds the row lock of that user's {@code authenticator} row, so the
 * check "not locked, not disabled", the 5-in-15-minutes and 20-in-24-hours counters and the lock are one atomic step
 * per {@code sub}.
 *
 * <p>verify, remove, reset, purge and the burning of codes call the secret store only outside that row lock: a seed is read
 * before the transaction, and the transaction compares ids and changes metadata. The confirmation of an enrollment is the
 * exception by design: it runs in one transaction under a transaction-scoped advisory lock of the user (not the row lock, so
 * verify never waits for it), and inside it reads the pending seed, writes the active seed, updates the row under its lock
 * and removes the seed it no longer needs. Confirmations of one user are therefore exclusive, and two parallel ones cannot
 * delete each other's seed. The order keeps one invariant: a row in state {@code active} always has its seed in the
 * store. Writes that precede a commit can leave an entry that no row accounts for, and a commit that fails after the
 * deletes leaves the row pending without its pending seed (the user starts again); {@link #sweepOrphanSeeds} removes
 * orphaned entries after {@link AuthenticatorLimits#ORPHAN_GRACE}.
 */
public class AuthenticatorService {

    /** How many times verify re-reads when a registration was replaced between reading the seed and taking the lock. */
    private static final int MAX_ATTEMPTS = 3;
    private static final int SWEEP_BATCH = 100;
    private static final Logger log = LoggerFactory.getLogger(AuthenticatorService.class);

    public enum VerifyResult {
        OK, INVALID, REPLAYED, BURNED, LOCKED, DISABLED, NOT_REGISTERED;

        public String wire() {
            return name().toLowerCase(Locale.ROOT);
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

    /** {@code pendingDestroyed}: the row no longer has an enrollment, so its stored seed is to be deleted. */
    private sealed interface ConfirmOutcome {
        record Active(Status status) implements ConfirmOutcome {
        }

        record WrongCode() implements ConfirmOutcome {
        }

        record Invalid(boolean pendingDestroyed) implements ConfirmOutcome {
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
            Instant now = clock.instant();
            String enrollmentId = "enr_" + randomToken(16);
            tx.executeWithoutResult(status -> reserveEnrollment(user.sub(), enrollmentId, now));

            byte[] seed = new byte[20];
            random.nextBytes(seed);
            // After the commit, so a refused or failed start never leaves a seed behind; if this write fails the
            // reserved id has no seed, which confirm treats as an invalid enrollment and the sweep clears.
            seeds.putPending(user.sub(), enrollmentId, seed);
            String secret = Base32.encode(seed);
            Arrays.fill(seed, (byte) 0);
            entry.ok("authenticator_enrollment_started");
            return new Enrollment(enrollmentId, otpauthUri(user.username(), secret), secret, now.plus(AuthenticatorLimits.ENROLLMENT_TTL));
        } catch (AuthenticatorRefusedException e) {
            entry.denied("authenticator_enrollment_failed", "rate_limited".equals(e.error()) ? "rate_limited" : null);
            throw e;
        } catch (RuntimeException e) {
            throw failed(entry, e);
        }
    }

    private void reserveEnrollment(String sub, String enrollmentId, Instant now) {
        AuthenticatorRecord row = repository.lockOrCreate(sub, now);
        if (row.state == State.ACTIVE) {
            throw new AuthenticatorRefusedException(409, "already_registered");
        }
        if (row.enrollWindowStart == null || !now.isBefore(row.enrollWindowStart.plus(AuthenticatorLimits.ENROLLMENT_START_WINDOW))) {
            row.enrollWindowStart = now;
            row.enrollStarts = 0;
        }
        if (row.enrollStarts >= config.enrollmentStartsPerHour()) {
            Instant reopens = row.enrollWindowStart.plus(AuthenticatorLimits.ENROLLMENT_START_WINDOW);
            throw new AuthenticatorRefusedException(429, "rate_limited", Math.max(1, Duration.between(now, reopens).toSeconds()));
        }
        row.enrollStarts++;
        row.pendingId = enrollmentId;
        row.pendingCreatedAt = now;
        row.pendingWrongCodes = 0;
        repository.save(row, now);
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

    /**
     * Confirmations of one user are exclusive: the first takes a transaction-scoped advisory lock, the others return
     * "invalid" at once without touching the secret store. Two parallel confirms of the same enrollment used to both
     * write the active seed, and the loser then deleted the winner's seed (an active row without a seed). The row lock
     * of verify is not held here; it is taken only for the final update, after the seeds are written.
     */
    private ConfirmOutcome confirm(String sub, String enrollmentId, String code) {
        String[] written = new String[1];
        return tx.execute(status -> confirmExclusively(sub, enrollmentId, code, written));
    }

    private ConfirmOutcome confirmExclusively(String sub, String enrollmentId, String code, String[] writtenRegistrationId) {
        if (!repository.tryConfirmLock(sub)) {
            return new ConfirmOutcome.Invalid(false);
        }
        Instant now = clock.instant();
        // Read after the lock: a confirm that held it before has committed by now.
        AuthenticatorRecord peek = repository.find(sub).orElse(null);
        if (peek == null || peek.pendingId == null || !peek.pendingId.equals(enrollmentId)) {
            return new ConfirmOutcome.Invalid(false);
        }
        Seed pending = seeds.getPending(sub).orElse(null);
        try {
            String registrationId = null;
            if (peek.state != State.ACTIVE && pending != null && pending.id().equals(enrollmentId)
                    && !pendingExpired(peek, now)
                    && Totp.matchingStep(pending.bytes(), code, now, AuthenticatorLimits.WINDOW_STEPS).isPresent()) {
                // The active seed is written before the update that makes the registration active. The old
                // entry is deleted first (all KV versions): a disabled registration's seed must not stay in the history.
                registrationId = randomHex(16);
                seeds.deleteActive(sub);
                seeds.putActive(sub, registrationId, pending.bytes());
                writtenRegistrationId[0] = registrationId;
            }
            ConfirmOutcome outcome = confirmLocked(sub, enrollmentId, code, pending, registrationId);
            // Still under the advisory lock: a confirm or a new enrollment of this user cannot slip in between the decision
            // and the removal of the seed it no longer needs, and delete the seed of the one that follows.
            cleanAfterConfirm(sub, outcome, registrationId);
            return outcome;
        } finally {
            if (pending != null) {
                Arrays.fill(pending.bytes(), (byte) 0);
            }
        }
    }

    /** The decision is committed; what remains in the store is housekeeping, and the sweep covers a failure here. */
    private void cleanAfterConfirm(String sub, ConfirmOutcome outcome, String writtenRegistrationId) {
        try {
            if (outcome instanceof ConfirmOutcome.Active
                    || outcome instanceof ConfirmOutcome.Invalid invalid && invalid.pendingDestroyed()) {
                seeds.deletePending(sub);
            }
            if (writtenRegistrationId != null && !(outcome instanceof ConfirmOutcome.Active)) {
                seeds.deleteActive(sub);
            }
        } catch (SecretStoreUnavailableException e) {
            log.warn("Could not delete an authenticator seed after an enrollment decision; the sweep will: {}", e.getMessage());
        }
    }

    private ConfirmOutcome confirmLocked(String sub, String enrollmentId, String code, Seed pending, String registrationId) {
        Instant now = clock.instant();
        AuthenticatorRecord row = repository.lock(sub).orElse(null);
        if (row == null || row.pendingId == null || !row.pendingId.equals(enrollmentId) || row.state == State.ACTIVE) {
            return new ConfirmOutcome.Invalid(false);
        }
        if (pendingExpired(row, now) || pending == null || !pending.id().equals(enrollmentId)) {
            row.clearPending();
            repository.save(row, now);
            return new ConfirmOutcome.Invalid(true);
        }
        OptionalLong step = Totp.matchingStep(pending.bytes(), code, now, AuthenticatorLimits.WINDOW_STEPS);
        if (step.isPresent() && registrationId != null) {
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
        if (step.isPresent()) {
            // Valid only because the window moved since the check before the transaction: no seed was written
            // for it, so ask for the code again without counting a wrong one.
            return new ConfirmOutcome.WrongCode();
        }
        row.pendingWrongCodes++;
        if (row.pendingWrongCodes >= AuthenticatorLimits.ENROLLMENT_MAX_WRONG_CODES) {
            row.clearPending();
            repository.save(row, now);
            return new ConfirmOutcome.Invalid(true);
        }
        repository.save(row, now);
        return new ConfirmOutcome.WrongCode();
    }

    private static boolean pendingExpired(AuthenticatorRecord row, Instant now) {
        return now.isAfter(row.pendingCreatedAt.plus(AuthenticatorLimits.ENROLLMENT_TTL));
    }

    /**
     * Deletes the seeds of enrollments that were never confirmed (CC-092: a pending seed does not outlive its 10
     * minutes). Without it an abandoned enrollment would keep its ciphertext in OpenBao until the user came back.
     *
     * @return how many enrollments were destroyed
     */
    public int sweepExpiredEnrollments() {
        Instant cutoff = clock.instant().minus(AuthenticatorLimits.ENROLLMENT_TTL);
        int destroyed = 0;
        for (String sub : repository.findPendingBefore(cutoff, SWEEP_BATCH)) {
            Boolean done = tx.execute(status -> {
                Instant now = clock.instant();
                AuthenticatorRecord row = repository.lock(sub).orElse(null);
                if (row == null || row.pendingId == null || !pendingExpired(row, now)) {
                    return false;
                }
                row.clearPending();
                repository.save(row, now);
                return true;
            });
            if (Boolean.TRUE.equals(done)) {
                seeds.deletePending(sub);
                destroyed++;
            }
        }
        return destroyed;
    }

    /**
     * Removes seeds in the store that no row accounts for: an active seed whose user has no registration, a pending
     * seed whose user has no enrollment. Such entries come from a write that preceded a transaction which then failed,
     * or from a delete after a commit that failed. Only entries older than the grace period are touched, because a
     * seed is written before the transaction that records it commits.
     *
     * @return how many entries were removed
     */
    public int sweepOrphanSeeds() {
        Instant cutoff = clock.instant().minus(AuthenticatorLimits.ORPHAN_GRACE);
        int removed = 0;
        for (AuthenticatorSeedStore.Entry entry : seeds.list()) {
            if (entry.updatedAt().isAfter(cutoff)) {
                continue;
            }
            AuthenticatorRecord row = repository.findBySubHash(entry.subHash()).orElse(null);
            boolean accounted = row != null && (entry.pending() ? row.pendingId != null : row.state != State.NONE);
            if (!accounted) {
                seeds.delete(entry);
                removed++;
            }
        }
        return removed;
    }

    /** Removal by the owner after a fresh MFA (BFF). Idempotent; a lock of the user stays (CC-091). */
    public void remove(Caller.PortalUser user) {
        AuditLog.Entry entry = audit.event("authenticator", user.requestId()).user(user.sub(), user.username(), user.azp());
        try {
            if (removeRegistration(user.sub())) {
                entry.ok("authenticator_removed");
            }
        } catch (RuntimeException e) {
            throw failed(entry, e);
        }
    }

    /** Reset by helpdesk (mTLS CN mcp-offboarding); {@code sub} is the target user. */
    public void reset(String requestId, String sub) {
        AuditLog.Entry entry = audit.event("authenticator", requestId).user(sub, null, null);
        try {
            if (removeRegistration(sub)) {
                entry.ok("authenticator_reset_by_admin");
            }
        } catch (RuntimeException e) {
            throw failed(entry, e);
        }
    }

    /**
     * Offboarding (mcp-offboarding, CC-155): the row goes, with the lock of the user (the user no longer exists, so
     * the lock has nothing left to protect), and so do both seeds. Row first and seeds after, like
     * {@link #removeRegistration}: a seed that outlives its row is harmless and the orphan sweep removes it. Idempotent.
     */
    public void purge(String requestId, String sub) {
        AuditLog.Entry entry = audit.event("authenticator", requestId).user(sub, null, null);
        try {
            boolean registered = Boolean.TRUE.equals(tx.execute(status -> {
                AuthenticatorRecord row = repository.lock(sub).orElse(null);
                if (row == null) {
                    return false;
                }
                boolean existed = row.state != State.NONE || row.pendingId != null;
                repository.delete(sub);
                return existed;
            }));
            seeds.deleteActive(sub);
            seeds.deletePending(sub);
            if (registered) {
                entry.ok("authenticator_removed");
            }
        } catch (RuntimeException e) {
            throw failed(entry, e);
        }
    }

    /**
     * The row goes to "none" first and commits; the seeds are deleted after. A failed delete answers 503 and the
     * caller repeats the (idempotent) request, which deletes unconditionally, also when no row is left. In between,
     * a seed without a registration is harmless.
     *
     * @return whether a registration or an enrollment existed (only that is worth an audit line)
     */
    private boolean removeRegistration(String sub) {
        boolean existed = Boolean.TRUE.equals(tx.execute(status -> {
            AuthenticatorRecord row = repository.lock(sub).orElse(null);
            if (row == null || (row.state == State.NONE && row.pendingId == null)) {
                return false;
            }
            row.clearRegistration();
            row.clearPending();
            repository.save(row, clock.instant());
            return true;
        }));
        seeds.deleteActive(sub);
        seeds.deletePending(sub);
        return existed;
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
            if (seed == null) {
                // Rows go active only after their seed is stored and leave it only before the seed is deleted, so an
                // active row without a seed means the store lost it. The registration cannot work again: drop it.
                if (dropRegistrationWithoutSeed(sub, peek.registrationId)) {
                    throw new AuthenticatorSeedMissingException();
                }
                continue;
            }
            try {
                Verified verified = tx.execute(status -> verifyLocked(sub, code, seed));
                if (verified != null) {
                    return verified;
                }
            } finally {
                Arrays.fill(seed.bytes(), (byte) 0);
            }
        }
        throw new SecretStoreUnavailableException("authenticator registration changed repeatedly during verification");
    }

    /** @return whether the row was still the same active registration and has been set back to "none" */
    private boolean dropRegistrationWithoutSeed(String sub, String registrationId) {
        return Boolean.TRUE.equals(tx.execute(status -> {
            AuthenticatorRecord row = repository.lock(sub).orElse(null);
            if (row == null || row.state != State.ACTIVE || !Objects.equals(row.registrationId, registrationId)) {
                return false;
            }
            row.clearRegistration();
            repository.save(row, clock.instant());
            return true;
        }));
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
        OptionalLong step = Totp.matchingStep(seed.bytes(), code, now, AuthenticatorLimits.WINDOW_STEPS);
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
        repository.deleteFailuresBefore(row.sub, now.minus(AuthenticatorLimits.DAILY_WINDOW));
        repository.addFailure(row.sub, now);
        if (repository.countFailures(row.sub, now.minus(AuthenticatorLimits.FAILURE_WINDOW), true) >= AuthenticatorLimits.MAX_FAILURES) {
            row.lockedUntil = now.plus(AuthenticatorLimits.LOCK_DURATION);
        }
        if (repository.countFailures(row.sub, now.minus(AuthenticatorLimits.DAILY_WINDOW), false) >= AuthenticatorLimits.DAILY_FAILURE_LIMIT) {
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
                .gatewayContext(claims.tool(), claims.prv());
    }

    private RuntimeException failed(AuditLog.Entry entry, RuntimeException e) {
        if (e instanceof AuthenticatorSeedMissingException) {
            entry.error("authenticator_seed_missing", "upstream_unavailable");
        } else if (e instanceof SecretStoreUnavailableException) {
            entry.error("secret_store_unavailable", "upstream_unavailable");
        } else if (CredentialService.unavailableDatabase(e)) {
            entry.error("database_unavailable", "upstream_unavailable");
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
                out.append('%').append(String.format(Locale.ROOT, "%02X", b & 0xff));
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
