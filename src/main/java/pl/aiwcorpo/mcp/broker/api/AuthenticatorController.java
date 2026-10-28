package pl.aiwcorpo.mcp.broker.api;

import java.time.temporal.ChronoUnit;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonInclude;

import jakarta.validation.Valid;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.CallerAuthenticationFilter;
import pl.aiwcorpo.mcp.broker.authenticator.AuthenticatorService;
import pl.aiwcorpo.mcp.broker.credential.InvalidRequestException;

/**
 * C4 authenticator group. The user is always the {@code sub} of the verified token; only the reset names another
 * user in its path, and only for the offboarding channel.
 */
@RestController
public class AuthenticatorController {

    private final AuthenticatorService authenticator;

    public AuthenticatorController(AuthenticatorService authenticator) {
        this.authenticator = authenticator;
    }

    @GetMapping(path = "/v1/authenticator", produces = "application/json")
    public ResponseEntity<AuthenticatorStatusResponse> status(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(AuthenticatorStatusResponse.of(authenticator.status(subOf(caller))));
    }

    @DeleteMapping(path = "/v1/authenticator")
    public ResponseEntity<Void> remove(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller) {
        authenticator.remove(portalUser(caller));
        return ResponseEntity.noContent().build();
    }

    /** The one response of C4 besides resolve that carries a secret: the seed, shown once (CC-092). */
    @PostMapping(path = "/v1/authenticator/enrollment", produces = "application/json")
    public ResponseEntity<EnrollmentResponse> startEnrollment(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller) {
        AuthenticatorService.Enrollment enrollment = authenticator.startEnrollment(portalUser(caller));
        return ResponseEntity.status(HttpStatus.CREATED)
                .cacheControl(CacheControl.noStore())
                .header("Pragma", "no-cache")
                .body(new EnrollmentResponse(enrollment.enrollmentId(), enrollment.otpauthUri(), enrollment.secret(),
                        enrollment.expiresAt().truncatedTo(ChronoUnit.SECONDS).toString()));
    }

    @PostMapping(path = "/v1/authenticator/enrollment/confirm", consumes = "application/json", produces = "application/json")
    public ResponseEntity<AuthenticatorStatusResponse> confirmEnrollment(
            @RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller,
            @Valid @RequestBody AuthenticatorRequests.ConfirmEnrollment request) {
        AuthenticatorService.Status status = authenticator.confirmEnrollment(portalUser(caller), request.enrollmentId(), request.code());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(AuthenticatorStatusResponse.of(status));
    }

    @PostMapping(path = "/v1/authenticator/verify", consumes = "application/json", produces = "application/json")
    public ResponseEntity<VerifyResponse> verify(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller,
            @Valid @RequestBody AuthenticatorRequests.Verify request) {
        AuthenticatorService.Verified verified = authenticator.verify(gateway(caller), request.code());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(new VerifyResponse(verified.result().wire(), verified.retryAfterSeconds()));
    }

    @PostMapping(path = "/v1/authenticator/invalidate-codes")
    public ResponseEntity<Void> invalidateCodes(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller) {
        authenticator.invalidateCodes(gateway(caller));
        return ResponseEntity.noContent().build();
    }

    @PostMapping(path = "/v1/admin/users/{sub}/authenticator/reset")
    public ResponseEntity<Void> reset(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller,
            @PathVariable("sub") String sub) {
        if (!(caller instanceof Caller.Offboarding offboarding)) {
            throw new IllegalStateException("reset reached without the offboarding channel");
        }
        if (sub.isBlank() || sub.length() > 255) {
            throw new InvalidRequestException("sub must be 1..255 characters");
        }
        authenticator.reset(offboarding.requestId(), sub);
        return ResponseEntity.noContent().build();
    }

    /** C4 AuthenticatorEnrollment. */
    public record EnrollmentResponse(String enrollmentId, String otpauthUri, String secret, String expiresAt) {

        @Override
        public String toString() {
            return "EnrollmentResponse[enrollmentId=" + enrollmentId + "]";
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record VerifyResponse(String result, Long retryAfterSeconds) {
    }

    private static String subOf(Caller caller) {
        return switch (caller) {
            case Caller.Gateway gateway when !gateway.claims().service() -> gateway.claims().sub();
            case Caller.PortalUser user -> user.sub();
            default -> throw new IllegalStateException("authenticator status reached without a user token");
        };
    }

    private static Caller.PortalUser portalUser(Caller caller) {
        if (!(caller instanceof Caller.PortalUser user)) {
            throw new IllegalStateException("authenticator operation reached without a portal user token");
        }
        return user;
    }

    private static Caller.Gateway gateway(Caller caller) {
        if (!(caller instanceof Caller.Gateway gateway) || gateway.claims().service()) {
            throw new IllegalStateException("authenticator operation reached without a gateway user token");
        }
        return gateway;
    }
}
