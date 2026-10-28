package pl.aiwcorpo.mcp.broker.system;

import java.util.Objects;

import pl.aiwcorpo.mcp.broker.secret.SecretValue;

/**
 * Tokens issued by an OAuth provider. {@code refreshToken} is null when the provider sent none (on refresh
 * it means the old one stays valid); {@code expiresInSeconds} is null when the provider did not say.
 */
public record TokenSet(SecretValue accessToken, SecretValue refreshToken, Long expiresInSeconds) {

    public TokenSet {
        Objects.requireNonNull(accessToken, "accessToken");
    }

    @Override
    public String toString() {
        return "TokenSet[***]";
    }
}
