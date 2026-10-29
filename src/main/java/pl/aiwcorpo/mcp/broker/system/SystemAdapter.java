package pl.aiwcorpo.mcp.broker.system;

import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;

/**
 * System-specific calls of the broker for the types where a user brings a credential (user-secret, user-oauth): whoami
 * here, the OAuth endpoints and revoke in {@link OAuthProvider}. The exchange of a token ({@link TokenExchanger}) and the
 * platform's own key ({@link ServiceAccountSource}) belong to systems that have no user credentials and no whoami.
 */
public interface SystemAdapter {

    /** Calls whoami with the credential and reports whose it is. Throws {@link UpstreamUnavailableException}. */
    WhoamiResult whoami(CredentialScheme scheme, SecretValue secret);
}
