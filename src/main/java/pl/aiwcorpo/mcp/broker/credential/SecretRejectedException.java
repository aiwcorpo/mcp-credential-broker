package pl.aiwcorpo.mcp.broker.credential;

/**
 * A 422 of C4: {@code secret_invalid} for a PAT, {@code flow_invalid} for an OAuth flow. Nothing was stored.
 * {@code reason} is the more specific
 * machine-readable cause that goes to the audit log only.
 */
public class SecretRejectedException extends RuntimeException {

    private final String error;
    private final String reason;

    public SecretRejectedException(String error) {
        this(error, error);
    }

    public SecretRejectedException(String error, String reason) {
        super(error);
        this.error = error;
        this.reason = reason;
    }

    public String error() {
        return error;
    }

    public String reason() {
        return reason;
    }
}
