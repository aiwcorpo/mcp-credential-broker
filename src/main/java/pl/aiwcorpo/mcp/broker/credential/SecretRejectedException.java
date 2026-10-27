package pl.aiwcorpo.mcp.broker.credential;

/** PUT secret refused (C4 422): {@code secret_invalid} or {@code identity_mismatch}. Nothing was stored. */
public class SecretRejectedException extends RuntimeException {

    private final String error;

    public SecretRejectedException(String error) {
        super(error);
        this.error = error;
    }

    public String error() {
        return error;
    }
}
