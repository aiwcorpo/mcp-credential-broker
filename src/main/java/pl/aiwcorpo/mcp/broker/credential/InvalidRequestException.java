package pl.aiwcorpo.mcp.broker.credential;

/** Caller error (400 invalid_request). The message is fixed text, never caller input. */
public class InvalidRequestException extends RuntimeException {

    public InvalidRequestException(String message) {
        super(message);
    }
}
