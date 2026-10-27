package pl.aiwcorpo.mcp.broker.system;

/** Outcome of a whoami call: the system either names the credential's owner or rejects the credential. */
public sealed interface WhoamiResult {

    record Identified(BackendIdentity identity) implements WhoamiResult {
    }

    record Rejected() implements WhoamiResult {
    }
}
