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

/**
 * Keys of the platform's own accounts in target systems, read from OpenBao KV
 * ({@code <kvMount>/data/<prefix>/<system>}, written by the operator, read-only for the broker). Fields: {@code value}
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
        JsonNode stored = client.read(kvMount + "/data/" + prefix + "/" + system);
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
}
