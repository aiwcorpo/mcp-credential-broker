package pl.aiwcorpo.mcp.broker.api;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import com.fasterxml.jackson.annotation.JsonInclude;

import pl.aiwcorpo.mcp.broker.authenticator.AuthenticatorService;

/** C4 AuthenticatorStatus: state and times only, never a seed. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthenticatorStatusResponse(String state, Instant registeredAt, Instant lastUsedAt, Instant lockedUntil,
        Instant disabledAt, String disabledReason) {

    static AuthenticatorStatusResponse of(AuthenticatorService.Status status) {
        return new AuthenticatorStatusResponse(status.state(), seconds(status.registeredAt()), seconds(status.lastUsedAt()),
                seconds(status.lockedUntil()), seconds(status.disabledAt()),
                status.disabledAt() == null ? null : "daily_failure_limit");
    }

    private static Instant seconds(Instant value) {
        return value == null ? null : value.truncatedTo(ChronoUnit.SECONDS);
    }
}
