package pl.aiwcorpo.mcp.broker.system;

import java.net.URI;
import java.util.List;

import pl.aiwcorpo.mcp.broker.secret.SecretValue;

/** Authorization code + PKCE client of one target system, acting as a confidential client (C4.2 user-oauth). */
public interface OAuthProvider {

    /** Provider URL the user's browser is sent to. */
    URI authorizeUrl(String state, String codeChallenge, URI redirectUri, List<String> scopes);

    /** Throws {@link OAuthGrantRejectedException} or {@link UpstreamUnavailableException}. */
    TokenSet exchangeCode(SecretValue code, SecretValue codeVerifier, URI redirectUri);

    /** Throws {@link OAuthGrantRejectedException} or {@link UpstreamUnavailableException}. */
    TokenSet refresh(SecretValue refreshToken);

    /** Asks the provider to invalidate a token. Throws {@link UpstreamUnavailableException}. */
    void revoke(SecretValue token);
}
