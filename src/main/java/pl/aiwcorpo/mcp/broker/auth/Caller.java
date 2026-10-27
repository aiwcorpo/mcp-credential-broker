package pl.aiwcorpo.mcp.broker.auth;

import java.util.Map;

/**
 * Authenticated caller of one request: client certificate CN plus a verified token. The user's
 * {@code sub} always comes from here, never from a path, query or body (C4).
 */
public sealed interface Caller {

    String requestId();

    /** Gateway with the internal JWT (C2). */
    record Gateway(String requestId, InternalJwtClaims claims) implements Caller {
    }

    /** Portal BFF with the user's token exchanged for aud=mcp-credential-broker. */
    record PortalUser(String requestId, String sub, String username, String azp, Map<String, Object> claims) implements Caller {

        /** SSO identity value used for C4.1 matching, e.g. preferred_username or email; null when absent. */
        public String identity(String claim) {
            return claims.get(claim) instanceof String value && !value.isBlank() ? value : null;
        }

        @Override
        public String toString() {
            return "PortalUser[sub=" + sub + ", username=" + username + "]";
        }
    }

    /** Offboarding webhook (CN only, no token). */
    record Offboarding(String requestId) implements Caller {
    }
}
