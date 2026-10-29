package pl.aiwcorpo.mcp.broker.oauth;

import java.time.Duration;
import java.util.Collection;
import java.util.Optional;

import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;

import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Flows in Redis under the broker's ACL prefix {@code broker:}: {@code <prefix>flow:<flowId>} holds the flow,
 * {@code <prefix>user:<sha256(sub)>:<system>} points at the user's pending flow. Only SET, GET, GETDEL and
 * DEL are used, all in the broker's ACL. The verifier is useless without the authorization code, which only
 * the provider's redirect to the portal carries, and the entry expires with the flow.
 */
public class RedisOAuthFlowStore implements OAuthFlowStore {

    private final StringRedisTemplate redis;
    private final String prefix;
    private final JsonMapper json;

    public RedisOAuthFlowStore(StringRedisTemplate redis, String prefix, JsonMapper json) {
        this.redis = redis;
        this.prefix = prefix;
        this.json = json;
    }

    @Override
    public void start(Flow flow, Duration ttl) {
        ObjectNode value = json.createObjectNode()
                .put("flowId", flow.flowId())
                .put("sub", flow.sub())
                .put("system", flow.system())
                .put("state", flow.state())
                .put("codeVerifier", flow.codeVerifier().reveal());
        String userKey = userKey(flow.sub(), flow.system());
        try {
            String earlier = redis.opsForValue().getAndDelete(userKey);
            if (earlier != null) {
                redis.delete(flowKey(earlier));
            }
            redis.opsForValue().set(flowKey(flow.flowId()), json.writeValueAsString(value), ttl);
            redis.opsForValue().set(userKey, flow.flowId(), ttl);
        } catch (DataAccessException e) {
            throw unavailable(e);
        }
    }

    @Override
    public Optional<Flow> peek(String flowId) {
        try {
            return parse(redis.opsForValue().get(flowKey(flowId)));
        } catch (DataAccessException e) {
            throw unavailable(e);
        }
    }

    @Override
    public Optional<Flow> take(String flowId) {
        try {
            return parse(redis.opsForValue().getAndDelete(flowKey(flowId)));
        } catch (DataAccessException e) {
            throw unavailable(e);
        }
    }

    @Override
    public int discardAll(String sub, Collection<String> systems) {
        int discarded = 0;
        try {
            for (String system : systems) {
                String flowId = redis.opsForValue().getAndDelete(userKey(sub, system));
                if (flowId != null && Boolean.TRUE.equals(redis.delete(flowKey(flowId)))) {
                    discarded++;
                }
            }
        } catch (DataAccessException e) {
            throw unavailable(e);
        }
        return discarded;
    }

    private Optional<Flow> parse(String stored) {
        if (stored == null) {
            return Optional.empty();
        }
        try {
            JsonNode node = json.readTree(stored);
            return Optional.of(new Flow(node.path("flowId").asString(), node.path("sub").asString(),
                    node.path("system").asString(), node.path("state").asString(),
                    SecretValue.of(node.path("codeVerifier").asString())));
        } catch (JacksonException | IllegalArgumentException e) {
            throw new SecretStoreUnavailableException("stored flow is not readable");
        }
    }

    private String flowKey(String flowId) {
        return prefix + "flow:" + flowId;
    }

    private String userKey(String sub, String system) {
        return prefix + "user:" + new SecretKey(sub, system, null).subHash() + ":" + system;
    }

    private static SecretStoreUnavailableException unavailable(DataAccessException e) {
        return new SecretStoreUnavailableException("oauth flow store unavailable: " + e.getClass().getSimpleName());
    }
}
