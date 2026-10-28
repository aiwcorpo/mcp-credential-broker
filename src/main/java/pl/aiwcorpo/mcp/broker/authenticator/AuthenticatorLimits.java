package pl.aiwcorpo.mcp.broker.authenticator;

import java.time.Duration;

/**
 * Values the contract fixes (C4, README of mcp-contracts "Potwierdzenia kodem TOTP", CC-091, CC-092, CC-126). They are
 * constants on purpose: a configuration value that widens the window or lengthens the enrollment would silently
 * leave the contract.
 */
final class AuthenticatorLimits {

    /** Steps accepted either side of the current one. */
    static final int WINDOW_STEPS = 1;
    static final int MAX_FAILURES = 5;
    static final Duration FAILURE_WINDOW = Duration.ofMinutes(15);
    static final Duration LOCK_DURATION = Duration.ofMinutes(15);
    static final int DAILY_FAILURE_LIMIT = 20;
    static final Duration DAILY_WINDOW = Duration.ofHours(24);
    static final Duration ENROLLMENT_TTL = Duration.ofMinutes(10);
    static final int ENROLLMENT_MAX_WRONG_CODES = 3;
    /** Window of the broker's own limit on enrollment starts. */
    static final Duration ENROLLMENT_START_WINDOW = Duration.ofHours(1);
    /**
     * A seed in OpenBao that no row accounts for is removed only after this long, because a seed is written
     * before the transaction that records it commits.
     */
    static final Duration ORPHAN_GRACE = Duration.ofMinutes(15);

    private AuthenticatorLimits() {
    }
}
