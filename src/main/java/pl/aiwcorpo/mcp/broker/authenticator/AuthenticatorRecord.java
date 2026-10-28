package pl.aiwcorpo.mcp.broker.authenticator;

import java.time.Instant;

/** Metadata row of one user's authenticator. Mutable on purpose: a service method loads it under lock, changes it, saves it. */
final class AuthenticatorRecord {

    enum State {
        NONE, ACTIVE, DISABLED;

        String wire() {
            return name().toLowerCase(java.util.Locale.ROOT);
        }

        static State fromWire(String value) {
            return valueOf(value.toUpperCase(java.util.Locale.ROOT));
        }
    }

    final String sub;
    State state = State.NONE;
    String registrationId;
    Instant registeredAt;
    Instant lastUsedAt;
    Long lastAcceptedStep;
    Long burnedThrough;
    Instant lockedUntil;
    Instant disabledAt;
    String pendingId;
    Instant pendingCreatedAt;
    int pendingWrongCodes;
    Instant enrollWindowStart;
    int enrollStarts;

    AuthenticatorRecord(String sub) {
        this.sub = sub;
    }

    boolean lockedAt(Instant now) {
        return lockedUntil != null && now.isBefore(lockedUntil);
    }

    void clearRegistration() {
        state = State.NONE;
        registrationId = null;
        registeredAt = null;
        lastUsedAt = null;
        lastAcceptedStep = null;
        burnedThrough = null;
        disabledAt = null;
    }

    void clearPending() {
        pendingId = null;
        pendingCreatedAt = null;
        pendingWrongCodes = 0;
    }
}
