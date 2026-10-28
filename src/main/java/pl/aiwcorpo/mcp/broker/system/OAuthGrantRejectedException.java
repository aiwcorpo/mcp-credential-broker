package pl.aiwcorpo.mcp.broker.system;

/**
 * The provider's token endpoint answered {@code invalid_grant}: the code was used, expired or does not match
 * the PKCE verifier, or the refresh token was revoked. Every other provider failure is an
 * {@link UpstreamUnavailableException}, because it points at the broker's configuration or the provider, not
 * at the user's grant.
 */
public class OAuthGrantRejectedException extends RuntimeException {

    public OAuthGrantRejectedException() {
        super("invalid_grant");
    }
}
