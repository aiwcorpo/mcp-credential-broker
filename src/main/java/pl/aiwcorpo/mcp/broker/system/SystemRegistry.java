package pl.aiwcorpo.mcp.broker.system;

import java.net.http.HttpClient;
import java.time.Clock;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import tools.jackson.databind.json.JsonMapper;

/** Target systems configured in the broker, with their adapters. */
public class SystemRegistry {

    /** SystemId of the contracts (common.schema.json); anything else is rejected before configuration is consulted. */
    public static final Set<String> KNOWN_SYSTEMS = Set.of("jira", "confluence", "gitlab", "servicedesk", "opensearch");

    private static final Set<CredentialType> USER_TYPES = Set.of(CredentialType.USER_SECRET, CredentialType.USER_OAUTH);
    private static final Set<String> USER_ADAPTERS = Set.of("gitlab", "atlassian-dc");

    /**
     * {@code adapter} (whoami) exists for the systems with user credentials; {@code exchanger} for token-exchange and
     * {@code serviceAccount} for service-account, and each of the three is null where it does not apply.
     */
    public record ConfiguredSystem(String id, BrokerProperties.SystemConfig config, SystemAdapter adapter,
            TokenExchanger exchanger, ServiceAccountSource serviceAccount) {

        public ConfiguredSystem(String id, BrokerProperties.SystemConfig config, SystemAdapter adapter) {
            this(id, config, adapter, null, null);
        }

        public boolean supports(CredentialType type) {
            return config.supportedTypes().contains(type);
        }

        /** The OAuth client of the system; present for every system that supports user-oauth. */
        public Optional<OAuthProvider> oauth() {
            return supports(CredentialType.USER_OAUTH) && adapter instanceof OAuthProvider provider
                    ? Optional.of(provider) : Optional.empty();
        }

        public Optional<TokenExchanger> tokenExchanger() {
            return supports(CredentialType.TOKEN_EXCHANGE) ? Optional.ofNullable(exchanger) : Optional.empty();
        }

        public Optional<ServiceAccountSource> serviceAccountSource() {
            return supports(CredentialType.SERVICE_ACCOUNT) ? Optional.ofNullable(serviceAccount) : Optional.empty();
        }
    }

    private final Map<String, ConfiguredSystem> systems;

    public SystemRegistry(Map<String, BrokerProperties.SystemConfig> config, HttpClient whoamiClient, JsonMapper json,
            OAuthClientSecrets clientSecrets, ServiceAccountKeys serviceAccountKeys, Clock clock, MeterRegistry meters) {
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
            requireCompatibleTypes(id, system);
            Object adapter = adapter(id, system, whoamiClient, json, clientSecrets, serviceAccountKeys, clock, meters);
            if (system.supportedTypes().contains(CredentialType.USER_OAUTH)
                    && (system.oauth() == null || !(adapter instanceof OAuthProvider))) {
                throw new IllegalArgumentException("broker.systems." + id + ": user-oauth needs an oauth client and an adapter that speaks OAuth");
            }
            configured.put(id, new ConfiguredSystem(id, system,
                    adapter instanceof SystemAdapter whoami ? whoami : null,
                    adapter instanceof TokenExchanger exchanger ? exchanger : null,
                    adapter instanceof ServiceAccountSource source ? source : null));
        });
        this.systems = Collections.unmodifiableMap(configured);
    }

    /**
     * token-exchange and service-account describe the whole system: the user has no connection to such a system, so
     * mixing them with user types would make one resolve mean two things.
     */
    private static void requireCompatibleTypes(String id, BrokerProperties.SystemConfig system) {
        for (CredentialType single : List.of(CredentialType.TOKEN_EXCHANGE, CredentialType.SERVICE_ACCOUNT)) {
            if (system.supportedTypes().contains(single) && !system.supportedTypes().equals(List.of(single))) {
                throw new IllegalArgumentException("broker.systems." + id + ": " + single.wire() + " cannot be combined with other types");
            }
        }
        boolean userTypes = system.supportedTypes().stream().anyMatch(USER_TYPES::contains);
        if (userTypes && !USER_ADAPTERS.contains(system.adapter())) {
            throw new IllegalArgumentException("broker.systems." + id + ": adapter " + system.adapter() + " has no user credentials");
        }
        if (!userTypes && USER_ADAPTERS.contains(system.adapter())) {
            throw new IllegalArgumentException("broker.systems." + id + ": adapter " + system.adapter() + " serves only user credentials");
        }
    }

    /** The adapter object implements the interfaces of the capabilities its system has. */
    private static Object adapter(String id, BrokerProperties.SystemConfig system, HttpClient http, JsonMapper json,
            OAuthClientSecrets clientSecrets, ServiceAccountKeys serviceAccountKeys, Clock clock, MeterRegistry meters) {
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
            case "opensearch" -> {
                if (!"opensearch".equals(id) || !system.supportedTypes().equals(List.of(CredentialType.TOKEN_EXCHANGE))
                        || system.tokenExchange() == null) {
                    throw new IllegalArgumentException("broker.systems." + id + ": adapter opensearch serves only opensearch,"
                            + " as token-exchange, and needs a token-exchange block");
                }
                BrokerProperties.TokenExchange exchange = system.tokenExchange();
                yield new OpenSearchAdapter(exchange, system.timeout(),
                        () -> clientSecrets.clientSecret(id, exchange.clientSecret()), http, json, clock, meters);
            }
            case "generic-rest" -> {
                if (!system.supportedTypes().equals(List.of(CredentialType.SERVICE_ACCOUNT))) {
                    throw new IllegalArgumentException("broker.systems." + id + ": adapter generic-rest serves only service-account");
                }
                yield new GenericRestAdapter(id, system.secretScheme(), serviceAccountKeys);
            }
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
