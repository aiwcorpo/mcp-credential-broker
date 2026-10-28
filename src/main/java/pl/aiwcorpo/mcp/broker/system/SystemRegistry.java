package pl.aiwcorpo.mcp.broker.system;

import java.net.http.HttpClient;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import tools.jackson.databind.json.JsonMapper;

/** Target systems configured in the broker, with their adapters. */
public class SystemRegistry {

    /** SystemId of the contracts (common.schema.json); anything else is rejected before configuration is consulted. */
    public static final Set<String> KNOWN_SYSTEMS = Set.of("jira", "confluence", "gitlab", "servicedesk", "opensearch");

    private static final Set<CredentialType> IMPLEMENTED_TYPES = Set.of(CredentialType.USER_SECRET, CredentialType.USER_OAUTH);

    public record ConfiguredSystem(String id, BrokerProperties.SystemConfig config, SystemAdapter adapter) {

        public boolean supports(CredentialType type) {
            return config.supportedTypes().contains(type);
        }

        /** The OAuth client of the system; present for every system that supports user-oauth. */
        public Optional<OAuthProvider> oauth() {
            return supports(CredentialType.USER_OAUTH) && adapter instanceof OAuthProvider provider
                    ? Optional.of(provider) : Optional.empty();
        }
    }

    private final Map<String, ConfiguredSystem> systems;

    public SystemRegistry(Map<String, BrokerProperties.SystemConfig> config, HttpClient whoamiClient, JsonMapper json,
            OAuthClientSecrets clientSecrets) {
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
            SystemAdapter adapter = adapter(id, system, whoamiClient, json, clientSecrets);
            if (system.supportedTypes().contains(CredentialType.USER_OAUTH)
                    && (system.oauth() == null || !(adapter instanceof OAuthProvider))) {
                throw new IllegalArgumentException("broker.systems." + id + ": user-oauth needs an oauth client and an adapter that speaks OAuth");
            }
            configured.put(id, new ConfiguredSystem(id, system, adapter));
        });
        this.systems = Collections.unmodifiableMap(configured);
    }

    private static SystemAdapter adapter(String id, BrokerProperties.SystemConfig system, HttpClient http, JsonMapper json,
            OAuthClientSecrets clientSecrets) {
        return switch (system.adapter()) {
            case "gitlab" -> {
                if (!"gitlab".equals(id)) {
                    throw new IllegalArgumentException("broker.systems." + id + ": adapter gitlab serves only gitlab");
                }
                Supplier<SecretValue> clientSecret = system.oauth() == null ? () -> {
                    throw new IllegalStateException("no OAuth client");
                } : () -> clientSecrets.clientSecret(id, system.oauth().clientSecret());
                yield new GitLabAdapter(system.baseUrl(), system.timeout(), system.oauth(), clientSecret, http, json);
            }
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
