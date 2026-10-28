package pl.aiwcorpo.mcp.broker.oauth;

import java.time.Duration;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;

import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;

/**
 * One refresh per (user, system) at a time across broker instances. Providers rotate refresh tokens, so two
 * parallel refreshes would make the second fail with invalid_grant and look like a revoked grant. SET NX EX
 * with an expiry longer than any refresh call; the lock is released explicitly, and an expired lock only
 * costs a second refresh attempt, which re-reads the connection first.
 */
public class RefreshLock {

    private static final Duration LEASE = Duration.ofSeconds(30);
    private static final long POLL_MILLIS = 100;

    private final StringRedisTemplate redis;
    private final String prefix;

    public RefreshLock(StringRedisTemplate redis, String prefix) {
        this.redis = redis;
        this.prefix = prefix;
    }

    /** Waits up to {@code wait} for the lock; returns false when it stays taken. */
    public boolean acquire(String sub, String system, Duration wait) {
        String key = key(sub, system);
        long deadline = System.nanoTime() + wait.toNanos();
        try {
            while (true) {
                if (Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(key, "1", LEASE))) {
                    return true;
                }
                if (System.nanoTime() >= deadline) {
                    return false;
                }
                Thread.sleep(POLL_MILLIS);
            }
        } catch (DataAccessException e) {
            throw new SecretStoreUnavailableException("refresh lock unavailable: " + e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    public void release(String sub, String system) {
        try {
            redis.delete(key(sub, system));
        } catch (DataAccessException e) {
            // The lease expires on its own.
        }
    }

    private String key(String sub, String system) {
        return prefix + "refresh:" + new SecretKey(sub, system, null).subHash() + ":" + system;
    }
}
