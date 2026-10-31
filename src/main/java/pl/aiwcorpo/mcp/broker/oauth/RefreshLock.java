package pl.aiwcorpo.mcp.broker.oauth;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;

import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;

/**
 * One writer per (user, system) at a time across broker instances: token refresh, disconnect, and replacing
 * a connection. Providers rotate refresh tokens, so two parallel refreshes would make the second fail with
 * invalid_grant and look like a revoked grant. SET NX PX with a random owner value and a lease longer than
 * the longest refresh the broker allows; only the owner releases the lock, by a script that compares and deletes
 * in one step on the Redis server (a plain GET and DEL could delete the lock of the next holder when the lease runs
 * out between them). A holder whose lease ran out while it worked still finishes, so the database write of every
 * holder is conditional on the secret version it read (fencing): a lock lost to expiry cannot overwrite a newer
 * state. The lock is held in Redis only, never in the memory of an instance, so a killed instance frees it when
 * its lease ends.
 */
public class RefreshLock {

    private static final long POLL_MILLIS = 100;
    private static final Logger log = LoggerFactory.getLogger(RefreshLock.class);
    private static final RedisScript<Long> RELEASE = new DefaultRedisScript<>(
            "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end", Long.class);
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
            redis.execute(RELEASE, List.of(key), owner);
        } catch (DataAccessException e) {
            log.warn("Refresh lock not released, the lease will expire ({})", e.getClass().getSimpleName());
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
