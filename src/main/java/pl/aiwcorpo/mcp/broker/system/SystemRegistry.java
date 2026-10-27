package pl.aiwcorpo.mcp.broker.system;

import java.net.http.HttpClient;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import tools.jackson.databind.json.JsonMapper;

/** Target systems configured in the broker, with their adapters. */
public class SystemRegistry {

    /** SystemId of the contracts (common.schema.json); anything else is rejected before configuration is consulted. */
    public static final Set<String> KNOWN_SYSTEMS = Set.of("jira", "confluence", "gitlab", "servicedesk", "opensearch");

    private static final Set<CredentialType> IMPLEMENTED_TYPES = Set.of(CredentialType.USER_SECRET);

    public record ConfiguredSystem(String id, BrokerProperties.SystemConfig config, SystemAdapter adapter) {

        public boolean supports(CredentialType type) {
            return config.supportedTypes().contains(type);
        }
    }

    private final Map<String, ConfiguredSystem> systems;

    public SystemRegistry(Map<String, BrokerProperties.SystemConfig> config, HttpClient whoamiClient, JsonMapper json) {
        Map<String, ConfiguredSystem> configured = new LinkedHashMap<>();
        config.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            String id = entry.getKey();
            BrokerProperties.SystemConfig system = entry.getValue();
            if (!KNOWN_SYSTEMS.contains(id)) {
                throw new IllegalArgumentException("broker.systems." + id + ": not a system id of the contracts");
            }
            if (!system.supportedTypes().contains(system.defaultType())) {
                throw new IllegalArgumentException("broker.systems." + id + ": default-type is not in supported-types");
            }
            for (CredentialType type : system.supportedTypes()) {
                if (!IMPLEMENTED_TYPES.contains(type)) {
                    throw new IllegalArgumentException("broker.systems." + id + ": credential type " + type.wire()
                            + " is not implemented in this version");
                }
            }
            configured.put(id, new ConfiguredSystem(id, system, adapter(id, system, whoamiClient, json)));
        });
        this.systems = Collections.unmodifiableMap(configured);
    }

    private static SystemAdapter adapter(String id, BrokerProperties.SystemConfig system, HttpClient http, JsonMapper json) {
        return switch (system.adapter()) {
            case "atlassian-dc" -> new AtlassianDcAdapter(atlassianProduct(id), system.baseUrl(), system.timeout(), http, json);
            default -> throw new IllegalArgumentException("broker.systems." + id + ": unknown adapter " + system.adapter());
        };
    }

    private static AtlassianDcAdapter.Product atlassianProduct(String id) {
        return switch (id) {
            case "jira" -> AtlassianDcAdapter.Product.JIRA;
            case "confluence" -> AtlassianDcAdapter.Product.CONFLUENCE;
            default -> throw new IllegalArgumentException("broker.systems." + id + ": adapter atlassian-dc serves only jira and confluence");
        };
    }

    public Optional<ConfiguredSystem> find(String id) {
        return Optional.ofNullable(systems.get(id));
    }

    public List<ConfiguredSystem> all() {
        return List.copyOf(systems.values());
    }
}
