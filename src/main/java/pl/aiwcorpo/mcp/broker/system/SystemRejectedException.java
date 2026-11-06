package pl.aiwcorpo.mcp.broker.system;

/** A configuration of a system the broker cannot serve; {@code reason} is the machine-readable part of C4 SystemRejected. */
public class SystemRejectedException extends RuntimeException {

    private final String reason;

    public SystemRejectedException(String reason, String message) {
        super(message);
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
