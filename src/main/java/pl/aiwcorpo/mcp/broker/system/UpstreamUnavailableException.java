package pl.aiwcorpo.mcp.broker.system;

/** The target system did not give a usable answer (timeout, 5xx, unexpected body). */
public class UpstreamUnavailableException extends RuntimeException {

    public UpstreamUnavailableException(String message) {
        super(message);
    }
}
