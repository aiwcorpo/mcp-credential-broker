package pl.aiwcorpo.mcp.broker.system;

/** Identity reported by the system's whoami (C4.1). {@code email} may be null. */
public record BackendIdentity(String username, String email) {
}
