package pl.aiwcorpo.mcp.broker.api;

import java.util.List;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.CallerAuthenticationFilter;
import pl.aiwcorpo.mcp.broker.system.SystemAdminService;

/** C4 listAdminSystems, getAdminSystem, putAdminSystem and deleteAdminSystem: the portal BFF with the token of an administrator. */
@RestController
public class SystemAdminController {

    private final SystemAdminService systems;

    public SystemAdminController(SystemAdminService systems) {
        this.systems = systems;
    }

    @GetMapping(path = "/v1/admin/systems", produces = "application/json")
    public ResponseEntity<List<SystemAdminView>> list(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(systems.list(portalUser(caller)));
    }

    @GetMapping(path = "/v1/admin/systems/{system}", produces = "application/json")
    public ResponseEntity<SystemAdminView> get(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller,
            @PathVariable("system") String system) {
        return stored(systems.get(portalUser(caller), system));
    }

    @PutMapping(path = "/v1/admin/systems/{system}", consumes = "application/json", produces = "application/json")
    public ResponseEntity<SystemAdminView> put(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller,
            @PathVariable("system") String system, @RequestHeader(value = "If-Match", required = false) String ifMatch,
            @RequestHeader(value = "If-None-Match", required = false) String ifNoneMatch,
            @Valid @RequestBody SystemAdminRequest request) {
        return stored(systems.put(portalUser(caller), system, request, ifMatch, ifNoneMatch));
    }

    @DeleteMapping(path = "/v1/admin/systems/{system}")
    public ResponseEntity<Void> delete(@RequestAttribute(CallerAuthenticationFilter.CALLER) Caller caller,
            @PathVariable("system") String system) {
        systems.delete(portalUser(caller), system);
        return ResponseEntity.noContent().build();
    }

    private static ResponseEntity<SystemAdminView> stored(SystemAdminService.Stored stored) {
        return ResponseEntity.ok().eTag("\"" + stored.etag() + "\"").cacheControl(CacheControl.noStore()).body(stored.view());
    }

    private static Caller.PortalUser portalUser(Caller caller) {
        if (!(caller instanceof Caller.PortalUser user)) {
            throw new IllegalStateException("admin systems reached without a portal user token");
        }
        return user;
    }
}
