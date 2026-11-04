package pl.aiwcorpo.mcp.broker.authenticator;

/**
 * Another verify of the same user is running on this instance. Answered 503 upstream_unavailable like any other
 * dependency failure: the attempt is not evaluated and not counted, so a refusal never tells a caller whether a code was right.
 */
public final class AuthenticatorBusyException extends RuntimeException {

    public AuthenticatorBusyException() {
        super("another verification of this user is in progress", null, false, false);
    }
}
