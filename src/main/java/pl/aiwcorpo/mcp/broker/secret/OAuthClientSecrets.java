package pl.aiwcorpo.mcp.broker.secret;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import tools.jackson.databind.JsonNode;

/**
 * The OAuth client secret of the broker at a provider (or at the IdP, for token exchange), kept in OpenBao KV
 * ({@code <kvMount>/data/<prefix>/<system>}, field {@code client_secret}). Written by the admin API of systems, read by the
 * adapters. A read is cached for a few minutes, keyed by the revision (etag) of the system: a write on another instance
 * changes the etag, which every instance sees within the poll interval of the registry, so a rotation does not wait for the
 * cache to expire.
 */
public class OAuthClientSecrets {

    private static final Duration CACHE = Duration.ofMinutes(5);

    private record Cached(SecretValue value, Instant fetchedAt, String revision) {
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

    /** @param revision the etag of the system definition the caller works with */
    public SecretValue clientSecret(String system, String revision) {
        Cached cached = cache.get(system);
        if (cached != null && Objects.equals(cached.revision(), revision) && cached.fetchedAt().plus(CACHE).isAfter(clock.instant())) {
            return cached.value();
        }
        String secret = read(system);
        if (secret == null || secret.isEmpty()) {
            throw new SecretStoreUnavailableException("no OAuth client secret for " + system + " in the secret store");
        }
        SecretValue value = SecretValue.of(secret);
        cache.put(system, new Cached(value, clock.instant(), revision));
        return value;
    }

    public boolean exists(String system) {
        String secret = read(system);
        return secret != null && !secret.isEmpty();
    }

    public void write(String system, SecretValue secret) {
        client.write(dataPath(system), client.object().set("data", client.object().put("client_secret", secret.reveal())));
        cache.remove(system);
    }

    /** Removes every version, so a later system with the same id starts without a secret. */
    public void delete(String system) {
        client.delete(kvMount + "/metadata/" + prefix + "/" + system);
        cache.remove(system);
    }

    private String read(String system) {
        JsonNode stored = client.read(dataPath(system));
        return stored == null ? null : stored.path("data").path("data").path("client_secret").asString(null);
    }

    private String dataPath(String system) {
        return kvMount + "/data/" + prefix + "/" + system;
    }
}
