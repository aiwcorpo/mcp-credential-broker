package pl.aiwcorpo.mcp.broker.system;

/** The IdP refused the token exchange: this user may not use the resource (C4 403 exchange_denied). */
public class ExchangeDeniedException extends RuntimeException {

    public ExchangeDeniedException() {
        super("token exchange refused by the IdP");
    }
}
