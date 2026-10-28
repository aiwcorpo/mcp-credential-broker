package pl.aiwcorpo.mcp.broker.authenticator;

import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;

/** An active registration whose seed is gone from the secret store; the registration has been dropped (answered 503 once). */
public class AuthenticatorSeedMissingException extends SecretStoreUnavailableException {

    public AuthenticatorSeedMissingException() {
        super("authenticator seed missing for an active registration");
    }
}
