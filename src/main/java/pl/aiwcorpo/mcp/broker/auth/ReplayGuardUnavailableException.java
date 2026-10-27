package pl.aiwcorpo.mcp.broker.auth;

public class ReplayGuardUnavailableException extends RuntimeException {

    public ReplayGuardUnavailableException(String message) {
        super(message);
    }
}
