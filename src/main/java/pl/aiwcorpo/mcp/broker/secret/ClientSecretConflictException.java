package pl.aiwcorpo.mcp.broker.secret;

/** The check-and-set of a client secret write failed: another change wrote a newer version first. */
public class ClientSecretConflictException extends RuntimeException {

    public ClientSecretConflictException() {
        super("the client secret changed while it was being written");
    }
}
