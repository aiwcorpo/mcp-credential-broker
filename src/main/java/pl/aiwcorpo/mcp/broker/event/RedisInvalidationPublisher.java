package pl.aiwcorpo.mcp.broker.event;

import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;

import tools.jackson.databind.json.JsonMapper;

/**
 * Redis pub/sub publisher. A lost message is tolerable because the gateway never caches longer than
 * cacheTtlSeconds (at most 60 s), so a failure is logged and does not fail the request.
 */
public class RedisInvalidationPublisher implements InvalidationPublisher {

    private static final Logger log = LoggerFactory.getLogger(RedisInvalidationPublisher.class);

    private final StringRedisTemplate redis;
    private final String channel;
    private final JsonMapper json;

    public RedisInvalidationPublisher(StringRedisTemplate redis, String channel, JsonMapper json) {
        this.redis = redis;
        this.channel = channel;
        this.json = json;
    }

    @Override
    public void invalidated(String sub, String system) {
        Map<String, String> event = new LinkedHashMap<>();
        event.put("sub", sub);
        event.put("system", system);
        try {
            redis.convertAndSend(channel, json.writeValueAsString(event));
        } catch (DataAccessException e) {
            log.warn("credential.invalidated for system {} not published ({})", system, e.getClass().getSimpleName());
        }
    }
}
