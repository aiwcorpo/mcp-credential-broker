package pl.aiwcorpo.mcp.broker.secret;

import java.util.Objects;

import pl.aiwcorpo.mcp.broker.credential.CredentialType;

/**
 * What the secret store keeps for one (sub, system). {@code refreshToken} is null for user-secret;
 * user-oauth (M2) stores the refresh token next to the access token.
 */
public record StoredCredential(CredentialType type, SecretValue value, SecretValue refreshToken) {

    public StoredCredential {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(value, "value");
    }

    public static StoredCredential of(CredentialType type, SecretValue value) {
        return new StoredCredential(type, value, null);
    }

    @Override
    public String toString() {
        return "StoredCredential[type=" + type + "]";
    }
}
