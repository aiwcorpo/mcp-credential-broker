package pl.aiwcorpo.mcp.broker.auth;

import java.time.Duration;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;

/** jti store in Redis: SET key NX EX under the broker's ACL prefix {@code jti:mcp-credential-broker:}. */
public class RedisReplayGuard implements ReplayGuard {

    private final StringRedisTemplate redis;
    private final String prefix;

    public RedisReplayGuard(StringRedisTemplate redis, String prefix) {
        this.redis = redis;
        this.prefix = prefix;
    }

    @Override
    public boolean firstUse(String jti, Duration ttl) {
        try {
            Boolean stored = redis.opsForValue().setIfAbsent(prefix + jti, "1", ttl);
            if (stored == null) {
                throw new ReplayGuardUnavailableException("no answer from the jti store");
            }
            return stored;
        } catch (DataAccessException e) {
            throw new ReplayGuardUnavailableException("jti store unavailable: " + e.getClass().getSimpleName());
        }
    }
}
