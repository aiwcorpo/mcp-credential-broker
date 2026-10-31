package pl.aiwcorpo.mcp.broker.secret;

/**
 * OpenBao answered 400 or 422 and named a reason. The reason is OpenBao's own text, never request content. Most of
 * these are the installation's fault (a missing key, a policy), which is {@link SecretStoreUnavailableException} like
 * any other refusal; only the callers that know what a particular text means may treat it otherwise.
 */
public class StoreRefusedException extends SecretStoreUnavailableException {

    private final String reason;

    public StoreRefusedException(String operation, int status, String reason) {
        super("secret store " + operation + " refused the request with HTTP " + status);
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
