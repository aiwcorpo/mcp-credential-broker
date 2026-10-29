package pl.aiwcorpo.mcp.broker.oauth;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;

import pl.aiwcorpo.mcp.broker.credential.RateLimitUnavailableException;
import pl.aiwcorpo.mcp.broker.credential.RateLimitedException;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;

/**
 * Fixed-window counters per (operation, user) in Redis under the broker's ACL prefix: INCR, and EXPIRE when the
 * counter is created. Only commands of the broker's ACL are used. A counter left without a TTL (the process died
 * between INCR and EXPIRE) would block the user for good, so an over-limit check that finds no TTL sets it. The
 * key names the user by the hash of {@code sub}, like the other broker keys.
 */
public class RateLimiter {

    private final StringRedisTemplate redis;
    private final String prefix;
    private final Duration window;

    public RateLimiter(StringRedisTemplate redis, String prefix, Duration window) {
        this.redis = redis;
        this.prefix = prefix;
        this.window = window;
    }

    /**
     * Counts one use of {@code operation} by {@code sub}.
     *
     * @throws RateLimitedException when this use is beyond {@code limit} in the current window
     * @throws RateLimitUnavailableException when Redis cannot be reached: without the counter the limit cannot be
     *         enforced, and the operations it protects need Redis anyway
     */
    public void check(String operation, String sub, int limit) {
        String key = prefix + operation + ":" + SecretKey.hashOf(sub);
        try {
            Long count = redis.opsForValue().increment(key);
            if (count == null) {
                throw new RateLimitUnavailableException("rate limit counter unavailable");
            }
            if (count == 1) {
                redis.expire(key, window);
            }
            if (count > limit) {
                Long ttl = redis.getExpire(key, TimeUnit.SECONDS);
                if (ttl == null || ttl < 0) {
                    redis.expire(key, window);
                    ttl = window.toSeconds();
                }
                throw new RateLimitedException(ttl);
            }
        } catch (DataAccessException e) {
            throw new RateLimitUnavailableException("rate limit counter unavailable: " + e.getClass().getSimpleName());
        }
    }
}
