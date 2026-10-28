package pl.aiwcorpo.mcp.broker.secret;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import tools.jackson.databind.JsonNode;

/**
 * The OAuth client secret of the broker at a provider, read from OpenBao KV
 * ({@code <kvMount>/data/<prefix>/<system>}, field {@code client_secret}) and kept in memory for a few minutes,
 * so a rotation in OpenBao takes effect without a restart. A missing entry falls back to the configured value
 * only when one is given, which the configuration allows in local development only.
 */
public class OAuthClientSecrets {

    private static final Duration CACHE = Duration.ofMinutes(5);

    private record Cached(SecretValue value, Instant fetchedAt) {
    }

    private final OpenBaoClient client;
    private final String kvMount;
    private final String prefix;
    private final Clock clock;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    public OAuthClientSecrets(OpenBaoClient client, String kvMount, String prefix, Clock clock) {
        this.client = client;
        this.kvMount = kvMount;
        this.prefix = prefix;
        this.clock = clock;
    }

    /** @param devFallback the secret from the environment, or null */
    public SecretValue clientSecret(String system, String devFallback) {
        Cached cached = cache.get(system);
        if (cached != null && cached.fetchedAt().plus(CACHE).isAfter(clock.instant())) {
            return cached.value();
        }
        JsonNode stored = client.read(kvMount + "/data/" + prefix + "/" + system);
        String secret = stored == null ? null : stored.path("data").path("data").path("client_secret").asString(null);
        if (secret == null || secret.isEmpty()) {
            if (devFallback == null || devFallback.isBlank()) {
                throw new SecretStoreUnavailableException("no OAuth client secret for " + system + " in the secret store");
            }
            secret = devFallback;
        }
        SecretValue value = SecretValue.of(secret);
        cache.put(system, new Cached(value, clock.instant()));
        return value;
    }
}
