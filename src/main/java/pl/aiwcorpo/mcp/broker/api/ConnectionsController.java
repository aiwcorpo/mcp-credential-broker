package pl.aiwcorpo.mcp.broker.api;

import java.time.temporal.ChronoUnit;
import java.util.List;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RestController;

import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.CallerAuthenticationFilter;
import pl.aiwcorpo.mcp.broker.credential.Connection;
import pl.aiwcorpo.mcp.broker.credential.CredentialService;

/** C4 listConnections and deleteConnection for the portal BFF; the user is always the token's sub. */
@RestController
public class ConnectionsController {

    private final CredentialService credentials;

    public ConnectionsController(CredentialService credentials) {
        this.credentials = credentials;
    }

    @GetMapping(path = "/v1/connections", produces = "application/json")
    public ResponseEntity<List<ConnectionResponse>> list(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller) {
        List<ConnectionResponse> body = credentials.connections(portalUser(caller)).stream()
                .map(listed -> {
                    Connection c = listed.connection();
                    return new ConnectionResponse(c.system(), c.type().wire(), listed.status().wire(), c.backendUser(),
                            c.expiresAt(), c.connectedAt(),
                            c.lastUsedAt() == null ? null : c.lastUsedAt().truncatedTo(ChronoUnit.SECONDS));
                })
                .toList();
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(body);
    }

    @DeleteMapping(path = "/v1/connections/{system}")
    public ResponseEntity<Void> delete(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller,
            @PathVariable("system") String system) {
        credentials.disconnect(portalUser(caller), system);
        return ResponseEntity.noContent().build();
    }

    private static Caller.PortalUser portalUser(Caller caller) {
        if (!(caller instanceof Caller.PortalUser user)) {
            throw new IllegalStateException("connections reached without a portal user token");
        }
        return user;
    }
}
