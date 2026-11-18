package pl.aiwcorpo.mcp.broker.secret;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Objects;

import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Keys of the platform's own accounts in target systems, read from OpenBao KV
 * ({@code <kvMount>/data/<prefix>/<system>}, written by an administrator through the admin API or by the operator). Fields: {@code value}
 * (the credential as it goes after the scheme in the header: for Basic already base64 of login:password), or
 * {@code username} (no colon) and {@code password} for a system that takes Basic, from which the broker builds that value; {@code expires_at} (RFC 3339) when the key is rotated on a schedule. Not cached: a rotation in
 * OpenBao takes effect on the next resolve, and the gateway's own cache is at most 60 seconds.
 */
public class ServiceAccountKeys {

    public record Key(SecretValue value, Instant expiresAt) {

        public Key {
            Objects.requireNonNull(value, "value");
        }

        @Override
        public String toString() {
            return "Key[expiresAt=" + expiresAt + "]";
        }
    }

    /**
     * What the entry says about itself and nothing of the key. {@code kvVersion}, {@code updatedAt} come from the version
     * metadata of KV v2, {@code expiresAt} from the entry, {@code updatedBy} from the field the admin API adds. Only
     * {@code set} is meaningful when there is no entry.
     */
    public record Status(boolean set, Integer kvVersion, Instant expiresAt, Boolean expired, Instant updatedAt, String updatedBy) {

        public static final Status MISSING = new Status(false, null, null, null, null, null);
    }

    /** The key as an administrator gives it: exactly one of {@code value} and the pair, never both. */
    public record Entry(String value, String username, String password, Instant expiresAt, String updatedBy) {

        @Override
        public String toString() {
            return "Entry[expiresAt=" + expiresAt + "]";
        }
    }

    private final OpenBaoClient client;
    private final String kvMount;
    private final String prefix;
    private final Clock clock;

    public ServiceAccountKeys(OpenBaoClient client, String kvMount, String prefix, Clock clock) {
        this.client = client;
        this.kvMount = kvMount;
        this.prefix = prefix;
        this.clock = clock;
    }

    /**
     * Fails closed: a missing, incomplete or expired key is {@link SecretStoreUnavailableException}, because nobody
     * can repair it from the user's side and an expired key would only be refused by the system.
     */
    public Key read(String system, CredentialScheme scheme) {
        JsonNode stored = client.read(dataPath(system));
        JsonNode data = stored == null ? null : stored.path("data").path("data");
        if (data == null || !data.isObject()) {
            throw new SecretStoreUnavailableException("no service account key for " + system + " in the secret store");
        }
        String value = value(data, scheme);
        if (value == null || value.isEmpty()) {
            throw new SecretStoreUnavailableException("service account entry for " + system + " has no usable value");
        }
        SecretValue secret = SecretValue.of(value);
        if (!secret.isHeaderToken()) {
            throw new SecretStoreUnavailableException("service account value for " + system + " is not a header token");
        }
        Instant expiresAt = expiry(data.path("expires_at"), system);
        if (expiresAt != null && !expiresAt.isAfter(clock.instant())) {
            throw new SecretStoreUnavailableException("service account key for " + system + " has expired");
        }
        return new Key(secret, expiresAt);
    }

    private static String value(JsonNode data, CredentialScheme scheme) {
        if (scheme == CredentialScheme.BASIC && data.path("username").isString() && data.path("password").isString()) {
            if (data.path("username").stringValue().contains(":")) {
                throw new SecretStoreUnavailableException("service account username must not contain a colon (RFC 7617)");
            }
            String login = data.path("username").stringValue() + ":" + data.path("password").stringValue();
            return Base64.getEncoder().encodeToString(login.getBytes(StandardCharsets.UTF_8));
        }
        return data.path("value").asString(null);
    }

    private static Instant expiry(JsonNode node, String system) {
        if (node.isMissingNode() || node.isNull() || (node.isString() && node.stringValue().isBlank())) {
            return null;
        }
        try {
            return Instant.parse(node.asString("")).truncatedTo(ChronoUnit.SECONDS);
        } catch (DateTimeException e) {
            throw new SecretStoreUnavailableException("service account expires_at for " + system + " is not a timestamp");
        }
    }

    /** Never throws for a missing or unusable entry: this is what the portal shows, not what resolve accepts. */
    public Status status(String system) {
        JsonNode stored = client.read(dataPath(system));
        JsonNode data = stored == null ? null : stored.path("data").path("data");
        if (data == null || !data.isObject()) {
            return Status.MISSING;
        }
        JsonNode metadata = stored.path("data").path("metadata");
        Instant expiresAt = lenientInstant(data.path("expires_at"));
        String updatedBy = data.path("updated_by").asString(null);
        return new Status(true, metadata.path("version").asInt(0) > 0 ? metadata.path("version").asInt() : null, expiresAt,
                expiresAt != null && !expiresAt.isAfter(clock.instant()), lenientInstant(metadata.path("created_time")),
                updatedBy == null || updatedBy.isEmpty() ? null : updatedBy);
    }

    /**
     * Replaces the whole entry with a new version: nothing of the previous one is merged and there is no check-and-set, the
     * last write wins. The status of the version written is returned.
     */
    public Status write(String system, Entry entry) {
        ObjectNode data = client.object();
        if (entry.value() != null) {
            data.put("value", entry.value());
        } else {
            data.put("username", entry.username()).put("password", entry.password());
        }
        Instant expiresAt = entry.expiresAt() == null ? null : entry.expiresAt().truncatedTo(ChronoUnit.SECONDS);
        if (expiresAt != null) {
            data.put("expires_at", expiresAt.toString());
        }
        if (entry.updatedBy() != null) {
            data.put("updated_by", entry.updatedBy());
        }
        JsonNode written = client.write(dataPath(system), client.object().set("data", data)).path("data");
        int version = written.path("version").asInt(0);
        if (version < 1) {
            throw new SecretStoreUnavailableException("secret store did not report the version of the service account key");
        }
        return new Status(true, version, expiresAt, false, lenientInstant(written.path("created_time")),
                entry.updatedBy());
    }

    /**
     * Removes the entry with every version (the metadata, not only the current version). The delete is always issued, so a
     * soft-deleted or unreadable current version does not keep older versions alive; the version read first is only for the
     * audit event and is null when no readable entry was there.
     */
    public Integer remove(String system) {
        Integer version = status(system).kvVersion();
        client.delete(kvMount + "/metadata/" + prefix + "/" + system);
        return version;
    }

    /** Whether the id has an entry, also one whose current version is soft-deleted. */
    public boolean exists(String system) {
        return client.present(dataPath(system));
    }

    /** Destroys one version (its data is gone, the history stays); an absent or already destroyed one is fine. */
    public void destroy(String system, int version) {
        client.write(kvMount + "/destroy/" + prefix + "/" + system, client.object()
                .set("versions", client.object().arrayNode().add(version)));
    }

    private String dataPath(String system) {
        return kvMount + "/data/" + prefix + "/" + system;
    }

    private static Instant lenientInstant(JsonNode node) {
        try {
            return node.isString() && !node.stringValue().isBlank() ? Instant.parse(node.stringValue()).truncatedTo(ChronoUnit.SECONDS) : null;
        } catch (DateTimeException e) {
            return null;
        }
    }
}
