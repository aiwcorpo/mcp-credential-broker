package pl.aiwcorpo.mcp.broker.secret;

/**
 * The store answered, but the entry cannot be used: it does not decrypt, belongs to another path or is incomplete. Unlike
 * a store that does not answer, repeating does not help; callers that must go on (a purge) can tell the two apart.
 */
public class SecretUnreadableException extends SecretStoreUnavailableException {

    public SecretUnreadableException(String message) {
        super(message);
    }
}
