package pl.aiwcorpo.mcp.broker.credential;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.StoredCredential;

/**
 * Writes a connection's value and metadata together. Each stored value gets its own path; the connection row
 * points at it. A replacement is written next to the old value and only the row switches, so a failure in
 * between leaves the previous credential intact, and the old path (all KV versions) is deleted only after
 * the switch.
 */
public class ConnectionStore {

    private static final Logger log = LoggerFactory.getLogger(ConnectionStore.class);
    private static final long[] RETRY_BACKOFF_MILLIS = {200, 600};
    /** Longer than the breaker of the secret store stays open: the provider has spent the old refresh token, so the new one is worth ~10 s of trying. */
    private static final long[] DEFAULT_ROTATION_RETRY_BACKOFF_MILLIS = {200, 500, 1000, 2000, 3000, 4000};

    private final ConnectionRepository connections;
    private final SecretStore secrets;
    private final InvalidationPublisher invalidations;
    private final Clock clock;

    /** One budget for the secret write and the row switch together: the lock lease of the refresh is 60 s. */
    private static final long ROTATION_BUDGET_NANOS = 15_000_000_000L;

    private final long[] rotationRetryBackoffMillis;

    public ConnectionStore(ConnectionRepository connections, SecretStore secrets, InvalidationPublisher invalidations, Clock clock) {
        this(connections, secrets, invalidations, clock, DEFAULT_ROTATION_RETRY_BACKOFF_MILLIS);
    }

    ConnectionStore(ConnectionRepository connections, SecretStore secrets, InvalidationPublisher invalidations, Clock clock,
            long[] rotationRetryBackoffMillis) {
        this.rotationRetryBackoffMillis = rotationRetryBackoffMillis;
        this.connections = connections;
        this.secrets = secrets;
        this.invalidations = invalidations;
        this.clock = clock;
    }

    /**
     * @param announce publish credential.invalidated when a previous connection existed (CC-046); false for a
     *                 token refresh, which keeps the same grant
     */
    Connection replace(Connection template, StoredCredential credential, Optional<Connection> previous, boolean announce) {
        SecretKey key = SecretKey.newVersion(template.sub(), template.system());
        secrets.put(key, credential);
        Connection next = template.withSecretVersion(key.version());
        try {
            connections.upsert(next, clock.instant());
        } catch (RuntimeException e) {
            deleteQuietly(key);
            throw e;
        }
        previous.ifPresent(old -> deleteQuietly(old.secretKey()));
        if (announce && previous.isPresent()) {
            invalidations.invalidated(template.sub(), template.system());
        }
        return next;
    }

    /**
     * Stores the tokens of a refresh next to the old value and switches the row only if it still points at the
     * version the refresh started from. Empty means the row changed in the meantime (disconnected, replaced):
     * the new value is removed again and the caller must revoke the new tokens at the provider.
     * The provider has already spent the old refresh token, so both writes are retried before giving up.
     */
    Optional<Connection> refresh(Connection current, StoredCredential credential, Instant accessExpiresAt) {
        SecretKey key = SecretKey.newVersion(current.sub(), current.system());
        long deadline = System.nanoTime() + ROTATION_BUDGET_NANOS;
        retrying(rotationRetryBackoffMillis, deadline, () -> {
            secrets.putRotated(key, credential);
            return null;
        });
        boolean switched;
        try {
            switched = retrying(rotationRetryBackoffMillis, deadline, () -> connections.switchSecretVersion(current.sub(), current.system(),
                    current.secretVersion(), key.version(), accessExpiresAt, clock.instant()));
        } catch (RuntimeException e) {
            // The update may have been committed with its answer lost on the way back: only the row can tell.
            switched = pointsAt(current, key).orElseThrow(() -> new RefreshOutcomeUnknownException(e));
            if (!switched) {
                deleteQuietly(key);
                throw e;
            }
        }
        if (!switched) {
            // A retry after a lost answer finds the version already changed and reports no match; the row decides.
            Optional<Boolean> now = pointsAt(current, key);
            if (now.isEmpty()) {
                throw new RefreshOutcomeUnknownException(null);
            }
            switched = now.get();
        }
        if (!switched) {
            deleteQuietly(key);
            return Optional.empty();
        }
        deleteQuietly(current.secretKey());
        return Optional.of(current.withSecretVersion(key.version()).withAccessExpiresAt(accessExpiresAt));
    }

    /** Whether the row of the connection now holds the version {@code key}; empty when the row cannot be read. */
    private Optional<Boolean> pointsAt(Connection current, SecretKey key) {
        try {
            return Optional.of(connections.find(current.sub(), current.system())
                    .map(row -> key.version().equals(row.secretVersion())).orElse(false));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    /**
     * The provider no longer honours the grant: the value is useless, the row stays so the portal shows "revoked".
     * Returns false when the row is no longer the one the caller read (nothing is changed then).
     */
    boolean markRevoked(Connection connection) {
        return markUnusable(connection, Connection.StoredState.REVOKED);
    }

    /** The grant is intact at the provider but the broker lost the rotated refresh token: only reconnecting helps. */
    boolean markError(Connection connection) {
        return markUnusable(connection, Connection.StoredState.ERROR);
    }

    private boolean markUnusable(Connection connection, Connection.StoredState state) {
        if (!connections.setStateIfVersion(connection.sub(), connection.system(), connection.secretVersion(), state, clock.instant())) {
            return false;
        }
        invalidations.invalidated(connection.sub(), connection.system());
        deleteQuietly(connection.secretKey());
        return true;
    }

    private <T> T retrying(Supplier<T> action) {
        return retrying(RETRY_BACKOFF_MILLIS, Long.MAX_VALUE, action);
    }

    /** @param deadlineNanos {@link System#nanoTime()} after which no further attempt is started (shared by the writes of one refresh) */
    private <T> T retrying(long[] backoff, long deadlineNanos, Supplier<T> action) {
        RuntimeException last = null;
        for (int attempt = 0; attempt < backoff.length + 1; attempt++) {
            try {
                return action.get();
            } catch (RuntimeException e) {
                last = e;
                if (attempt < backoff.length) {
                    long wait = backoff[attempt];
                    if (deadlineNanos != Long.MAX_VALUE && deadlineNanos - System.nanoTime() <= wait * 1_000_000L) {
                        break;
                    }
                    pause(wait);
                }
            }
        }
        throw last;
    }

    private void retryingVoid(Runnable action) {
        retrying(() -> {
            action.run();
            return null;
        });
    }

    private static void pause(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    void deleteQuietly(SecretKey key) {
        try {
            retryingVoid(() -> secrets.delete(key));
        } catch (RuntimeException e) {
            log.error("Unreferenced secret for system {} could not be removed, the orphan sweep will ({})", key.system(),
                    e.getClass().getSimpleName());
        }
    }
}
