package pl.aiwcorpo.mcp.broker.system;

/** A refused admin call, with the status and the C4 body it is answered with ({@code reason} and {@code message} only for 422). */
public class SystemAdminException extends RuntimeException {

    private final int status;
    private final String error;
    private final String reason;

    public SystemAdminException(int status, String error, String reason, String message) {
        super(message);
        this.status = status;
        this.error = error;
        this.reason = reason;
    }

    public static SystemAdminException forbidden() {
        return new SystemAdminException(403, "forbidden", null, null);
    }

    public static SystemAdminException stepUpRequired() {
        return new SystemAdminException(401, "step_up_required", null, null);
    }

    public static SystemAdminException notFound() {
        return new SystemAdminException(404, "not_found", null, null);
    }

    public static SystemAdminException invalid(String message) {
        return new SystemAdminException(400, "invalid_request", null, message);
    }

    public static SystemAdminException preconditionFailed() {
        return new SystemAdminException(412, "precondition_failed", null, null);
    }

    public static SystemAdminException preconditionRequired() {
        return new SystemAdminException(428, "precondition_required", null, null);
    }

    public static SystemAdminException rejected(SystemRejectedException e) {
        return new SystemAdminException(422, "system_rejected", e.reason(), e.getMessage());
    }

    public int status() {
        return status;
    }

    public String error() {
        return error;
    }

    public String reason() {
        return reason;
    }
}
