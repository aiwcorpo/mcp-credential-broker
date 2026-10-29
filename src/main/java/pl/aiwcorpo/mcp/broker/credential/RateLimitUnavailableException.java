package pl.aiwcorpo.mcp.broker.credential;

/** The counter of a rate limit could not be read or written (Redis); the request is refused with 503, fail-closed. */
public class RateLimitUnavailableException extends RuntimeException {

    public RateLimitUnavailableException(String message) {
        super(message);
    }
}
