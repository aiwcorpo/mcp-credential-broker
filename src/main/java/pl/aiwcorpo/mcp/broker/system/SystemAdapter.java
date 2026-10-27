package pl.aiwcorpo.mcp.broker.system;

import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;

/**
 * System-specific calls of the broker. M1 needs only whoami; OAuth endpoints and revoke (M2, M4) are
 * added here per adapter.
 */
public interface SystemAdapter {

    /** Calls whoami with the credential and reports whose it is. Throws {@link UpstreamUnavailableException}. */
    WhoamiResult whoami(CredentialScheme scheme, SecretValue secret);
}
