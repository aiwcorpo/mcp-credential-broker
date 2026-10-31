package pl.aiwcorpo.mcp.broker.auth;

import java.util.List;

/**
 * Verified claims of the gateway's internal JWT (C2). In the service variant ({@link #service()}) only
 * sub, rid, prv and jti are set.
 */
public record InternalJwtClaims(
        String sub,
        String usr,
        List<String> grp,
        String azp,
        String tool,
        String rid,
        String prv,
        String jti,
        boolean service) {

    public static final String SERVICE_SUB = "system:mcp-gateway";
}
