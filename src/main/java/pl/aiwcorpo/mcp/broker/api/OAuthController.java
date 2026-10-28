package pl.aiwcorpo.mcp.broker.api;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.CallerAuthenticationFilter;
import pl.aiwcorpo.mcp.broker.credential.OAuthService;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;

/** C4 startOAuth and completeOAuth for the portal BFF; the user is always the token's sub. */
@RestController
public class OAuthController {

    private final OAuthService oauth;

    public OAuthController(OAuthService oauth) {
        this.oauth = oauth;
    }

    @PostMapping(path = "/v1/connections/{system}/oauth/start", consumes = "application/json", produces = "application/json")
    public ResponseEntity<OAuthStartResponse> start(
            @RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller,
            @PathVariable("system") String system,
            @Valid @RequestBody OAuthStartRequest request) {
        OAuthService.Started started = oauth.start(portalUser(caller), system, request.returnPath());
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(new OAuthStartResponse(started.authorizeUrl().toString(), started.flowId()));
    }

    @PostMapping(path = "/v1/connections/{system}/oauth/complete", consumes = "application/json", produces = "application/json")
    public ResponseEntity<OAuthCompleteResponse> complete(
            @RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller,
            @PathVariable("system") String system,
            @Valid @RequestBody OAuthCompleteRequest request) {
        OAuthService.Completed completed = oauth.complete(portalUser(caller), system, request.flowId(),
                SecretValue.of(request.code()), request.state());
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(new OAuthCompleteResponse(completed.status().wire(), completed.backendUser()));
    }

    private static Caller.PortalUser portalUser(Caller caller) {
        if (!(caller instanceof Caller.PortalUser user)) {
            throw new IllegalStateException("OAuth reached without a portal user token");
        }
        return user;
    }
}
