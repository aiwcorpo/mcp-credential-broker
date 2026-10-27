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
        boolean serviceVariantAllowed, InternalJwtVerifier.ToolClaim toolClaim, String auditEvent) {

    public static final String GATEWAY = "mcp-gateway";
    public static final String PORTAL_BFF = "mcp-portal-bff";

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

    public static final List<Operation> ALL = List.of(RESOLVE, PUT_SECRET, LIST_SYSTEMS, LIST_CONNECTIONS, DELETE_CONNECTION);

    private static final Pattern SYSTEM_IN_PATH = Pattern.compile("^/v1/connections/([^/;]+)(?:/|$)");

    /** System named in a connection path, or null; the audit log keeps only known system ids. */
    public static String systemOf(String path) {
        Matcher matcher = SYSTEM_IN_PATH.matcher(path);
        return matcher.find() ? matcher.group(1) : null;
    }

    public static Optional<Operation> match(String method, String path) {
        return ALL.stream().filter(op -> op.method.equals(method) && op.path.matcher(path).matches()).findFirst();
    }
}
