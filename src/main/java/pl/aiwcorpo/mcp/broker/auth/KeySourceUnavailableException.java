package pl.aiwcorpo.mcp.broker.auth;

/**
 * Keys needed to verify a token cannot be obtained (JWKS endpoint down, or the last good copy is too old).
 * Answered with 503 instead of 401, so an outage is not reported to callers as their own fault.
 */
public class KeySourceUnavailableException extends RuntimeException {

    public KeySourceUnavailableException(String message) {
        super(message);
    }
}
