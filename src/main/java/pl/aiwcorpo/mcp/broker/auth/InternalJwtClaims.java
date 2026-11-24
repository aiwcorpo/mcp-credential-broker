package pl.aiwcorpo.mcp.broker.auth;

import java.util.List;

/**
 * Verified claims of the gateway's internal JWT (C2). In the service variant ({@link #service()}) only
 * sub, rid, prv (the revision of the gateway policy data, a counter) and jti are set. {@code resource} (CC-260) is the
 * URI of a resources/read that the resolve serves, instead of {@code tool}; {@code pty} is {@code agent} or
 * {@code delegated} and null for a human; {@code act} is set exactly for {@code delegated}.
 */
public record InternalJwtClaims(
        String sub,
        String usr,
        List<String> grp,
        String azp,
        String tool,
        String rid,
        long prv,
        String jti,
        boolean service,
        String resource,
        String pty,
        Actor act) {

    public static final String SERVICE_SUB = "system:mcp-gateway";
    public static final String PTY_AGENT = "agent";
    public static final String PTY_DELEGATED = "delegated";

    /** The agent that acts for the person in {@code sub} (RFC 8693 actor). */
    public record Actor(String sub, String azp) {
    }

    public InternalJwtClaims(String sub, String usr, List<String> grp, String azp, String tool, String rid, long prv, String jti,
            boolean service) {
        this(sub, usr, grp, azp, tool, rid, prv, jti, service, null, null, null);
    }

    public boolean isAgent() {
        return PTY_AGENT.equals(pty);
    }
}
