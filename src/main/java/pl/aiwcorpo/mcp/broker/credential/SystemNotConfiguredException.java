package pl.aiwcorpo.mcp.broker.credential;

/**
 * A system of the contracts that this broker has no configuration for (C4 422 system_not_configured, CC-158): a
 * defect of the installation, not of the request.
 */
public class SystemNotConfiguredException extends RuntimeException {

    public SystemNotConfiguredException(String system) {
        super("system " + system + " is not configured in the broker");
    }
}
