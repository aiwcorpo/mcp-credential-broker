package pl.aiwcorpo.mcp.broker.system;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

/**
 * Bounds on the calls to target systems. A provider that answers slowly holds one request thread per call for the whole
 * timeout, so the calls in flight to one system are capped and a call over the cap is refused at once instead of waiting:
 * a slow system then costs at most {@code perSystem} threads and the other systems and operations keep theirs. The permits
 * are keyed by system id, not held by an adapter, so the calls of an adapter replaced by a change still count.
 *
 * <p>A refresh holds the refresh lock while it waits for the provider; a timeout at or over the lock's lease would let a
 * second refresh of the same connection start and spend the refresh token twice. Timeouts are therefore kept below the
 * lease: the admin API refuses a longer one, and a longer one already stored is served shortened.
 */
public final class UpstreamLimits {

    private final int perSystem;
    private final Duration refreshLockLease;
    private final Map<String, Semaphore> inFlight = new ConcurrentHashMap<>();

    public UpstreamLimits(int perSystem, Duration refreshLockLease) {
        if (perSystem < 1) {
            throw new IllegalArgumentException("at least one call per system");
        }
        if (refreshLockLease.compareTo(Duration.ofSeconds(1)) <= 0) {
            throw new IllegalArgumentException("refresh lock lease must be longer than one second");
        }
        this.perSystem = perSystem;
        this.refreshLockLease = refreshLockLease;
    }

    Semaphore inFlight(String system) {
        return inFlight.computeIfAbsent(system, id -> new Semaphore(perSystem));
    }

    /** Whether an administrator may set this timeout for a system. */
    public boolean allowsTimeout(Duration timeout) {
        return timeout.compareTo(refreshLockLease) < 0;
    }

    /** The timeout a call is made with: the configured one, or one second under the lease when the configured one is not allowed. */
    public Duration effectiveTimeout(Duration configured) {
        return allowsTimeout(configured) ? configured : refreshLockLease.minusSeconds(1);
    }
}
