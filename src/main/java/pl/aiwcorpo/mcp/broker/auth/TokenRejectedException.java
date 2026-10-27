package pl.aiwcorpo.mcp.broker.auth;

/**
 * A bearer token was rejected (HTTP 401). {@code reason} is a fixed snake_case code (the names follow the
 * C2 test vectors) and is safe to log; the token itself never is.
 */
public class TokenRejectedException extends RuntimeException {

    private final String reason;

    public TokenRejectedException(String reason) {
        super(reason);
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
