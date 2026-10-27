package pl.aiwcorpo.mcp.broker.credential;

/** The user has no usable connection for the system (C4 409 credential_required). */
public class CredentialRequiredException extends RuntimeException {

    private final String system;

    public CredentialRequiredException(String system) {
        super("credential_required");
        this.system = system;
    }

    public String system() {
        return system;
    }
}
