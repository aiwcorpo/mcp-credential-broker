package pl.aiwcorpo.mcp.broker.auth;

import java.time.Duration;

/** Remembers internal JWT ids (C2 {@code jti}) for their validity window. */
public interface ReplayGuard {

    /**
     * Records the id. Returns false when it was already recorded. Throws {@link ReplayGuardUnavailableException}
     * when the store cannot answer, so the caller fails closed.
     */
    boolean firstUse(String jti, Duration ttl);
}
