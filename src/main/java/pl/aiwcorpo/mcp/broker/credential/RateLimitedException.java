package pl.aiwcorpo.mcp.broker.credential;

/** A per-user limit of the broker was exceeded (C4 429 rate_limited, CC-156). */
public class RateLimitedException extends RuntimeException {

    private final long retryAfterSeconds;

    public RateLimitedException(long retryAfterSeconds) {
        super("rate limit exceeded");
        this.retryAfterSeconds = Math.max(1, retryAfterSeconds);
    }

    /** Seconds until the window reopens, at least 1. */
    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
