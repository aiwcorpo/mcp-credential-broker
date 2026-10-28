package pl.aiwcorpo.mcp.broker.authenticator;

/** A request the broker answers with a C4 error body: {@code {"error": error}} and the given HTTP status. */
public class AuthenticatorRefusedException extends RuntimeException {

    private final int status;
    private final String error;

    public AuthenticatorRefusedException(int status, String error) {
        super(error);
        this.status = status;
        this.error = error;
    }

    public int status() {
        return status;
    }

    public String error() {
        return error;
    }
}
