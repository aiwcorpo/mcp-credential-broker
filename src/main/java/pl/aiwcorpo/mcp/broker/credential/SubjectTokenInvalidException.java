package pl.aiwcorpo.mcp.broker.credential;

/**
 * The subjectToken of a token-exchange resolve failed the checks of CC-157: signature, issuer, audience, expiry or a
 * sub other than the one of the internal JWT. The message names no cause, so the answer does not tell the gateway
 * (or whoever sits behind it) which check failed.
 */
public class SubjectTokenInvalidException extends InvalidRequestException {

    public SubjectTokenInvalidException() {
        super("subjectToken does not belong to the caller");
    }
}
