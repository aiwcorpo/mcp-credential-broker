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

    /** Helpdesk or IGA with the client certificate CN mcp-offboarding and no token (C4 admin operations). */
    record Offboarding(String requestId) implements Caller {
    }

    /** Portal BFF with the user's token exchanged for aud=mcp-credential-broker. */
    record PortalUser(String requestId, String sub, String username, String azp, Map<String, Object> claims) implements Caller {

        /** SSO identity value used for C4.1 matching, e.g. preferred_username or email; null when absent. */
        public String identity(String claim) {
            return claims.get(claim) instanceof String value && !value.isBlank() ? value : null;
        }

        /** When the user last authenticated (claim {@code auth_time}, seconds), or null when the token does not say. */
        public java.time.Instant authTime() {
            return switch (claims.get("auth_time")) {
                case Number seconds -> java.time.Instant.ofEpochSecond(seconds.longValue());
                case java.time.Instant instant -> instant;
                case null, default -> null;
            };
        }

        /** Group of the {@code groups} claim of the IdP token. */
        public boolean hasGroup(String group) {
            return claims.get("groups") instanceof java.util.Collection<?> groups && groups.contains(group);
        }

        @Override
        public String toString() {
            return "PortalUser[sub=" + sub + ", username=" + username + "]";
        }
    }
}
