package pl.aiwcorpo.mcp.broker.credential;

import pl.aiwcorpo.mcp.broker.system.UpstreamUnavailableException;

/** A purge of the user is under way or has just run: writes that would put the user back are refused (503, audit reason user_offboarding). */
public class UserBeingOffboardedException extends UpstreamUnavailableException {

    public UserBeingOffboardedException() {
        super("this user is being offboarded");
    }
}
