package pl.aiwcorpo.mcp.broker.api;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;

@RestController
public class SystemsController {

    private final SystemRegistry systems;

    public SystemsController(SystemRegistry systems) {
        this.systems = systems;
    }

    @GetMapping(path = "/v1/systems", produces = "application/json")
    public List<SystemInfoResponse> systems() {
        return systems.all().stream()
                .map(s -> new SystemInfoResponse(s.id(),
                        s.config().supportedTypes().stream().map(CredentialType::wire).distinct().toList(),
                        s.config().defaultType().wire(),
                        s.config().oauthScopes().stream().distinct().toList(),
                        s.config().deployment() == null ? null : s.config().deployment().wire(),
                        s.supports(CredentialType.USER_SECRET) ? (s.config().userSecretIsBasic() ? "Basic" : "Bearer") : null))
                .toList();
    }
}
