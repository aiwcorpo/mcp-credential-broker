package pl.aiwcorpo.mcp.broker.authenticator;

/** A request the broker answers with a C4 error body: {@code {"error": error}} and the given HTTP status. */
public class AuthenticatorRefusedException extends RuntimeException {

    private final int status;
    private final String error;
    private final Long retryAfterSeconds;

    public AuthenticatorRefusedException(int status, String error) {
        this(status, error, null);
    }

    public AuthenticatorRefusedException(int status, String error, Long retryAfterSeconds) {
        super(error);
        this.status = status;
        this.error = error;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    /** Seconds after which the same request can succeed, or null. */
    public Long retryAfterSeconds() {
        return retryAfterSeconds;
    }

    public int status() {
        return status;
    }

    public String error() {
        return error;
    }
}
