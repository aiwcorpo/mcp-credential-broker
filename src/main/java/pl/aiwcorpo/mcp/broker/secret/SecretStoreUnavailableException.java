package pl.aiwcorpo.mcp.broker.secret;

/** The secret store cannot be used right now. Never carries store responses, which may hold plaintext. */
public class SecretStoreUnavailableException extends RuntimeException {

    public SecretStoreUnavailableException(String message) {
        super(message);
    }
}
