package pl.aiwcorpo.mcp.broker.system;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * SystemId of common.schema.json. The reserved ids are the CNs of platform components and prefixes of server certificates
 * (mcp-gateway, mcp-offboarding, ...), so no system may take them.
 */
public final class SystemIds {

    public static final Set<String> RESERVED = Set.of("gateway", "offboarding", "portal", "broker", "prometheus", "platform",
            "admin", "registry", "adapter", "internal", "ci");

    private static final Pattern SHAPE = Pattern.compile("^[a-z][a-z0-9]{1,30}$");

    private SystemIds() {
    }

    public static boolean isReserved(String id) {
        return id != null && RESERVED.contains(id);
    }

    /** Matches the shape of a SystemId, reserved ids included. */
    public static boolean hasValidShape(String id) {
        return id != null && SHAPE.matcher(id).matches();
    }

    /** Matches SystemId exactly: the shape, and not reserved. */
    public static boolean isValid(String id) {
        return hasValidShape(id) && !isReserved(id);
    }
}
