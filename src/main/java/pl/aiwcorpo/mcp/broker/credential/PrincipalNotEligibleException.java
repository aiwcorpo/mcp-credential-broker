package pl.aiwcorpo.mcp.broker.credential;

/** The principal of the token (an autonomous agent) may not have a credential of this system (C4 403 principal_not_eligible, CC-261). */
public class PrincipalNotEligibleException extends RuntimeException {

    public PrincipalNotEligibleException() {
        super("principal type may not use this system");
    }
}
