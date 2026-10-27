package pl.aiwcorpo.mcp.broker.auth;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Operations served by this version with the client certificate CNs allowed for each, mirroring
 * {@code x-allowed-client-cn} of openapi/credential-broker.v1.yaml (checked by OperationsContractTest).
 * Anything not listed is answered 404 before any token is looked at.
 */
public record Operation(String operationId, String method, Pattern path, Set<String> allowedCns,
        boolean serviceVariantAllowed, String auditEvent) {

    public static final String GATEWAY = "mcp-gateway";
    public static final String PORTAL_BFF = "mcp-portal-bff";
    public static final String OFFBOARDING = "mcp-offboarding";

    public static final Operation RESOLVE = new Operation("resolveCredential", "POST",
            Pattern.compile("^/v1/credentials/resolve$"), Set.of(GATEWAY), false, "credential_resolve");
    public static final Operation PUT_SECRET = new Operation("putSecret", "PUT",
            Pattern.compile("^/v1/connections/[^/]+/secret$"), Set.of(PORTAL_BFF), false, "connection_change");
    public static final Operation LIST_SYSTEMS = new Operation("listSystems", "GET",
            Pattern.compile("^/v1/systems$"), Set.of(GATEWAY, PORTAL_BFF), true, null);

    public static final List<Operation> ALL = List.of(RESOLVE, PUT_SECRET, LIST_SYSTEMS);

    public static Optional<Operation> match(String method, String path) {
        return ALL.stream().filter(op -> op.method.equals(method) && op.path.matcher(path).matches()).findFirst();
    }
}
