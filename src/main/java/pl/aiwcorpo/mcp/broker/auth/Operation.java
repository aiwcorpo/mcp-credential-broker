package pl.aiwcorpo.mcp.broker.auth;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Operations served by this version with the client certificate CNs allowed for each, mirroring
 * {@code x-allowed-client-cn} of openapi/credential-broker.v1.yaml (checked by OperationsContractTest).
 * Anything not listed is answered 404 before any token is looked at.
 */
public record Operation(String operationId, String method, Pattern path, Set<String> allowedCns,
        boolean serviceVariantAllowed, InternalJwtVerifier.ToolClaim toolClaim, String auditEvent, boolean tokenless) {

    public static final String GATEWAY = "mcp-gateway";
    public static final String PORTAL_BFF = "mcp-portal-bff";
    public static final String OFFBOARDING = "mcp-offboarding";

    public Operation(String operationId, String method, Pattern path, Set<String> allowedCns,
            boolean serviceVariantAllowed, InternalJwtVerifier.ToolClaim toolClaim, String auditEvent) {
        this(operationId, method, path, allowedCns, serviceVariantAllowed, toolClaim, auditEvent, false);
    }

    public static final Operation RESOLVE = new Operation("resolveCredential", "POST",
            Pattern.compile("^/v1/credentials/resolve$"), Set.of(GATEWAY), false, InternalJwtVerifier.ToolClaim.REQUIRED, "credential_resolve");
    public static final Operation PUT_SECRET = new Operation("putSecret", "PUT",
            Pattern.compile("^/v1/connections/[^/]+/secret$"), Set.of(PORTAL_BFF), false, InternalJwtVerifier.ToolClaim.FORBIDDEN, "connection_change");
    public static final Operation LIST_SYSTEMS = new Operation("listSystems", "GET",
            Pattern.compile("^/v1/systems$"), Set.of(GATEWAY, PORTAL_BFF), true, InternalJwtVerifier.ToolClaim.FORBIDDEN, null);

    public static final Operation LIST_CONNECTIONS = new Operation("listConnections", "GET",
            Pattern.compile("^/v1/connections$"), Set.of(PORTAL_BFF), false, InternalJwtVerifier.ToolClaim.FORBIDDEN, null);
    public static final Operation DELETE_CONNECTION = new Operation("deleteConnection", "DELETE",
            Pattern.compile("^/v1/connections/[^/]+$"), Set.of(PORTAL_BFF), false, InternalJwtVerifier.ToolClaim.FORBIDDEN,
            "connection_change");

    public static final Operation START_OAUTH = new Operation("startOAuth", "POST",
            Pattern.compile("^/v1/connections/[^/]+/oauth/start$"), Set.of(PORTAL_BFF), false, InternalJwtVerifier.ToolClaim.FORBIDDEN,
            "connection_change");
    public static final Operation COMPLETE_OAUTH = new Operation("completeOAuth", "POST",
            Pattern.compile("^/v1/connections/[^/]+/oauth/complete$"), Set.of(PORTAL_BFF), false, InternalJwtVerifier.ToolClaim.FORBIDDEN,
            "connection_change");

    /** Gateway and BFF both read the state; the gateway's token names the tool being confirmed (CC-092). */
    public static final Operation GET_AUTHENTICATOR = new Operation("getAuthenticator", "GET",
            Pattern.compile("^/v1/authenticator$"), Set.of(GATEWAY, PORTAL_BFF), false, InternalJwtVerifier.ToolClaim.REQUIRED, null);
    public static final Operation DELETE_AUTHENTICATOR = new Operation("deleteAuthenticator", "DELETE",
            Pattern.compile("^/v1/authenticator$"), Set.of(PORTAL_BFF), false, InternalJwtVerifier.ToolClaim.FORBIDDEN, "authenticator");
    public static final Operation START_ENROLLMENT = new Operation("startAuthenticatorEnrollment", "POST",
            Pattern.compile("^/v1/authenticator/enrollment$"), Set.of(PORTAL_BFF), false, InternalJwtVerifier.ToolClaim.FORBIDDEN,
            "authenticator");
    public static final Operation CONFIRM_ENROLLMENT = new Operation("confirmAuthenticatorEnrollment", "POST",
            Pattern.compile("^/v1/authenticator/enrollment/confirm$"), Set.of(PORTAL_BFF), false,
            InternalJwtVerifier.ToolClaim.FORBIDDEN, "authenticator");
    public static final Operation VERIFY_CODE = new Operation("verifyAuthenticatorCode", "POST",
            Pattern.compile("^/v1/authenticator/verify$"), Set.of(GATEWAY), false, InternalJwtVerifier.ToolClaim.REQUIRED, "authenticator");
    public static final Operation INVALIDATE_CODES = new Operation("invalidateAuthenticatorCodes", "POST",
            Pattern.compile("^/v1/authenticator/invalidate-codes$"), Set.of(GATEWAY), false, InternalJwtVerifier.ToolClaim.REQUIRED,
            "authenticator");
    public static final Operation RESET_AUTHENTICATOR = new Operation("resetUserAuthenticator", "POST",
            Pattern.compile("^/v1/admin/users/[^/]+/authenticator/reset$"), Set.of(OFFBOARDING), false,
            InternalJwtVerifier.ToolClaim.FORBIDDEN, "authenticator", true);

    public static final Operation PURGE_USER = new Operation("purgeUser", "POST",
            Pattern.compile("^/v1/admin/users/[^/]+/purge$"), Set.of(OFFBOARDING), false,
            InternalJwtVerifier.ToolClaim.FORBIDDEN, "admin_change", true);

    public static final Operation LIST_ADMIN_SYSTEMS = new Operation("listAdminSystems", "GET",
            Pattern.compile("^/v1/admin/systems$"), Set.of(PORTAL_BFF), false, InternalJwtVerifier.ToolClaim.FORBIDDEN, "admin_change");
    public static final Operation GET_ADMIN_SYSTEM = new Operation("getAdminSystem", "GET",
            Pattern.compile("^/v1/admin/systems/[^/]+$"), Set.of(PORTAL_BFF), false, InternalJwtVerifier.ToolClaim.FORBIDDEN, "admin_change");
    public static final Operation PUT_ADMIN_SYSTEM = new Operation("putAdminSystem", "PUT",
            Pattern.compile("^/v1/admin/systems/[^/]+$"), Set.of(PORTAL_BFF), false, InternalJwtVerifier.ToolClaim.FORBIDDEN, "admin_change");
    public static final Operation DELETE_ADMIN_SYSTEM = new Operation("deleteAdminSystem", "DELETE",
            Pattern.compile("^/v1/admin/systems/[^/]+$"), Set.of(PORTAL_BFF), false, InternalJwtVerifier.ToolClaim.FORBIDDEN, "admin_change");

    public static final List<Operation> ALL = List.of(RESOLVE, PUT_SECRET, LIST_SYSTEMS, LIST_CONNECTIONS, DELETE_CONNECTION,
            START_OAUTH, COMPLETE_OAUTH, GET_AUTHENTICATOR, DELETE_AUTHENTICATOR, START_ENROLLMENT, CONFIRM_ENROLLMENT,
            VERIFY_CODE, INVALIDATE_CODES, RESET_AUTHENTICATOR, PURGE_USER, LIST_ADMIN_SYSTEMS, GET_ADMIN_SYSTEM, PUT_ADMIN_SYSTEM,
            DELETE_ADMIN_SYSTEM);

    private static final Pattern SYSTEM_IN_PATH = Pattern.compile("^/v1/(?:connections|admin/systems)/([^/;]+)(?:/|$)");

    /** System named in a connection path, or null; the audit log keeps only known system ids. */
    public static String systemOf(String path) {
        Matcher matcher = SYSTEM_IN_PATH.matcher(path);
        return matcher.find() ? matcher.group(1) : null;
    }

    public static Optional<Operation> match(String method, String path) {
        return ALL.stream().filter(op -> op.method.equals(method) && op.path.matcher(path).matches()).findFirst();
    }
}
