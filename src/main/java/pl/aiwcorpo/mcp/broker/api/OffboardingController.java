package pl.aiwcorpo.mcp.broker.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RestController;

import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.CallerAuthenticationFilter;
import pl.aiwcorpo.mcp.broker.credential.InvalidRequestException;
import pl.aiwcorpo.mcp.broker.credential.OffboardingService;

/** C4 purgeUser: the offboarding channel (certificate CN mcp-offboarding, no token) names the user in the path. */
@RestController
public class OffboardingController {

    private final OffboardingService offboarding;

    public OffboardingController(OffboardingService offboarding) {
        this.offboarding = offboarding;
    }

    @PostMapping(path = "/v1/admin/users/{sub}/purge")
    public ResponseEntity<Void> purge(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller,
            @PathVariable("sub") String sub) {
        if (!(caller instanceof Caller.Offboarding channel)) {
            throw new IllegalStateException("purge reached without the offboarding channel");
        }
        if (sub.isBlank() || sub.length() > 255) {
            throw new InvalidRequestException("sub must be 1..255 characters");
        }
        offboarding.purge(channel.requestId(), sub);
        return ResponseEntity.noContent().build();
    }
}
