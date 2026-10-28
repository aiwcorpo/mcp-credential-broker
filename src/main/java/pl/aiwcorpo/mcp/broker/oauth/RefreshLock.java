package pl.aiwcorpo.mcp.broker.oauth;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;

import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;

/**
 * One writer per (user, system) at a time across broker instances: token refresh, disconnect, and replacing
 * a connection. Providers rotate refresh tokens, so two parallel refreshes would make the second fail with
 * invalid_grant and look like a revoked grant. SET NX PX with a random owner value and a lease longer than
 * the longest refresh the broker allows; only the owner releases the lock. The release compares and deletes
 * in two commands because the Redis ACL of the broker has no scripting; the window between them matters only
 * if the lease runs out in that instant, and the database write of every holder is conditional on the secret
 * version it read (fencing), so a lock lost to expiry cannot overwrite a newer state.
 */
public class RefreshLock {

    private static final long POLL_MILLIS = 100;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final StringRedisTemplate redis;
    private final String prefix;
    private final Duration lease;

    public RefreshLock(StringRedisTemplate redis, String prefix, Duration lease) {
        this.redis = redis;
        this.prefix = prefix;
        this.lease = lease;
    }

    /** Waits up to {@code wait} for the lock; the result is the owner value to release with, empty when it stays taken. */
    public Optional<String> acquire(String sub, String system, Duration wait) {
        String key = key(sub, system);
        String owner = randomOwner();
        long deadline = System.nanoTime() + wait.toNanos();
        try {
            while (true) {
                if (Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(key, owner, lease))) {
                    return Optional.of(owner);
                }
                if (System.nanoTime() >= deadline) {
                    return Optional.empty();
                }
                Thread.sleep(POLL_MILLIS);
            }
        } catch (DataAccessException e) {
            throw new SecretStoreUnavailableException("refresh lock unavailable: " + e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    public void release(String sub, String system, String owner) {
        String key = key(sub, system);
        try {
            if (owner.equals(redis.opsForValue().get(key))) {
                redis.delete(key);
            }
        } catch (DataAccessException e) {
            // The lease expires on its own.
        }
    }

    private String key(String sub, String system) {
        return prefix + "refresh:" + new SecretKey(sub, system, null).subHash() + ":" + system;
    }

    private static String randomOwner() {
        byte[] value = new byte[16];
        RANDOM.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
