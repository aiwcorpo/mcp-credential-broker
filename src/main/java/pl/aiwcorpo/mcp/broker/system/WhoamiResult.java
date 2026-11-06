package pl.aiwcorpo.mcp.broker.system;

/** Outcome of a whoami call: the system names the credential's owner, rejects the credential, or cannot say. */
public sealed interface WhoamiResult {

    record Identified(BackendIdentity identity) implements WhoamiResult {
    }

    record Rejected() implements WhoamiResult {
    }

    /** The system has no whoami (a generic-rest system without one): the credential is taken as it is and no owner is known. */
    record Unverified() implements WhoamiResult {
    }
}
