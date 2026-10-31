package pl.aiwcorpo.mcp.broker.credential;

import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;

/**
 * The row of a connection was switched to the rotated credential, or was not, and the broker cannot read the row to
 * tell which. Nothing is deleted and no token is revoked on this path: either could destroy the only copy that works.
 */
public class RefreshOutcomeUnknownException extends SecretStoreUnavailableException {

    public RefreshOutcomeUnknownException(Throwable cause) {
        super("the outcome of switching the connection to the refreshed credential is unknown");
        if (cause != null) {
            initCause(cause);
        }
    }
}
