package pl.aiwcorpo.mcp.broker.secret;

import java.util.Objects;

import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;

/**
 * What the secret store keeps for one (sub, system). {@code refreshToken} is null for user-secret; {@code scheme} is set only for a Basic pair (CC-222), so a change of the system's
 * configuration later cannot turn a pair into a Bearer header;
 * user-oauth (M2) stores the refresh token next to the access token.
 */
public record StoredCredential(CredentialType type, SecretValue value, SecretValue refreshToken, CredentialScheme scheme) {

    public StoredCredential {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(value, "value");
    }

    public StoredCredential(CredentialType type, SecretValue value, SecretValue refreshToken) {
        this(type, value, refreshToken, null);
    }

    public static StoredCredential of(CredentialType type, SecretValue value) {
        return new StoredCredential(type, value, null, null);
    }

    /** A user secret with the scheme it was given in: Basic for a login and password pair, null for a single token. */
    public static StoredCredential userSecret(SecretValue value, CredentialScheme scheme) {
        return new StoredCredential(CredentialType.USER_SECRET, value, null, scheme);
    }

    public boolean isBasic() {
        return scheme == CredentialScheme.BASIC;
    }

    @Override
    public String toString() {
        return "StoredCredential[type=" + type + "]";
    }
}
