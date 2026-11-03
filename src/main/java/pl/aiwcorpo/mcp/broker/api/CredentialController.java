package pl.aiwcorpo.mcp.broker.api;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.CallerAuthenticationFilter;
import pl.aiwcorpo.mcp.broker.credential.CredentialService;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;

@RestController
public class CredentialController {

    private final CredentialService credentials;

    public CredentialController(CredentialService credentials) {
        this.credentials = credentials;
    }

    @PostMapping(path = "/v1/credentials/resolve", consumes = "application/json", produces = "application/json")
    public ResponseEntity<ResolvedCredentialResponse> resolve(
            @RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller,
            @Valid @RequestBody ResolveRequest request) {
        if (!(caller instanceof Caller.Gateway gateway) || gateway.claims().service()) {
            throw new IllegalStateException("resolve reached without a gateway user token");
        }
        CredentialService.Resolved resolved = credentials.resolve(gateway, request.system(), request.scopes(),
                request.subjectToken());
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header("Pragma", "no-cache")
                .body(new ResolvedCredentialResponse(resolved.scheme().wire(), resolved.value().reveal(),
                        resolved.type().wire(), resolved.expiresAt(), resolved.cacheTtlSeconds()));
    }

    @PutMapping(path = "/v1/connections/{system}/secret", consumes = "application/json", produces = "application/json")
    public ResponseEntity<PutSecretResponse> putSecret(
            @RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller,
            @PathVariable("system") String system,
            @Valid @RequestBody PutSecretRequest request) {
        if (!(caller instanceof Caller.PortalUser user)) {
            throw new IllegalStateException("PUT secret reached without a portal user token");
        }
        CredentialService.Stored stored = credentials.putSecret(user, system, request.username(),
                SecretValue.of(request.secret()), request.expiresAt());
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(new PutSecretResponse(stored.status().wire(), stored.backendUser(), stored.expiresAt()));
    }
}
