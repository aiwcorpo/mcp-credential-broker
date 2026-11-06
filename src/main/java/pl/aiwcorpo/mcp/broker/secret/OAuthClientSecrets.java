package pl.aiwcorpo.mcp.broker.secret;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import tools.jackson.databind.JsonNode;

/**
 * The client secrets of the admin-managed systems, in OpenBao KV v2 at {@code <kvMount>/data/<prefix>/<system>}, field
 * {@code client_secret}, a prefix of their own. A write is a check-and-set against the current version and returns the new
 * version; the system row stores it together with its new etag, and every reader asks for exactly that version, so a secret
 * written by one change is never read with the configuration of another. A version is immutable, so a cached value is keyed
 * by (system, version) and is never stale. Versions that no row points at are destroyed, not left behind.
 *
 * <p>{@code legacyPrefix} is where 1.x read its secrets; it is read only by the import of the 1.x properties.
 */
public class OAuthClientSecrets {

    private static final Duration CACHE = Duration.ofMinutes(5);

    private record Key(String system, int version) {
    }

    private record Cached(SecretValue value, Instant fetchedAt) {
    }

    private final OpenBaoClient client;
    private final String kvMount;
    private final String prefix;
    private final String legacyPrefix;
    private final Clock clock;
    private final Map<Key, Cached> cache = new ConcurrentHashMap<>();

    public OAuthClientSecrets(OpenBaoClient client, String kvMount, String prefix, String legacyPrefix, Clock clock) {
        this.client = client;
        this.kvMount = kvMount;
        this.prefix = prefix;
        this.legacyPrefix = legacyPrefix;
        this.clock = clock;
    }

    /** The secret of exactly this version. */
    public SecretValue read(String system, Integer version) {
        if (version == null) {
            throw new SecretStoreUnavailableException("no OAuth client secret for " + system);
        }
        Key key = new Key(system, version);
        Cached cached = cache.get(key);
        if (cached != null && cached.fetchedAt().plus(CACHE).isAfter(clock.instant())) {
            return cached.value();
        }
        JsonNode stored = client.read(dataPath(system) + "?version=" + version);
        String secret = stored == null ? null : stored.path("data").path("data").path("client_secret").asString(null);
        if (secret == null || secret.isEmpty()) {
            throw new SecretStoreUnavailableException("no OAuth client secret for " + system + " in the secret store");
        }
        SecretValue value = SecretValue.of(secret);
        cache.put(key, new Cached(value, clock.instant()));
        return value;
    }

    /**
     * Writes a new version if the current one is still the one read a moment ago.
     *
     * @throws ClientSecretConflictException when another write came in between
     * @return the new version
     */
    public int write(String system, SecretValue secret) {
        JsonNode metadata = client.read(kvMount + "/metadata/" + prefix + "/" + system);
        int current = metadata == null ? 0 : metadata.path("data").path("current_version").asInt(0);
        try {
            JsonNode written = client.write(dataPath(system), client.object()
                    .set("options", client.object().put("cas", current))
                    .set("data", client.object().put("client_secret", secret.reveal())));
            return written.path("data").path("version").asInt(current + 1);
        } catch (StoreRefusedException e) {
            throw new ClientSecretConflictException();
        }
    }

    /** Destroys one version (the data is gone, the history stays). Absent or already destroyed is fine. */
    public void destroy(String system, int version) {
        client.write(kvMount + "/destroy/" + prefix + "/" + system, client.object()
                .set("versions", client.object().arrayNode().add(version)));
        cache.remove(new Key(system, version));
    }

    /** The secret 1.x kept for the system, for the import only. */
    public Optional<SecretValue> readLegacy(String system) {
        JsonNode stored = client.read(kvMount + "/data/" + legacyPrefix + "/" + system);
        String secret = stored == null ? null : stored.path("data").path("data").path("client_secret").asString(null);
        return secret == null || secret.isEmpty() ? Optional.empty() : Optional.of(SecretValue.of(secret));
    }

    private String dataPath(String system) {
        return kvMount + "/data/" + prefix + "/" + system;
    }
}
