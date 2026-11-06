package pl.aiwcorpo.mcp.broker.system;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;

/**
 * The systems of this instance: a snapshot of the table {@code target_system} with the adapters built for it. The snapshot is
 * replaced by {@link #reload()}, which the admin API calls after its own write and {@link SystemRegistryRefreshJob} calls
 * every few seconds, so a change made on any instance reaches all of them without a restart. An entry whose etag did not
 * change keeps its adapter object.
 */
public class SystemRegistry {

    private static final Logger log = LoggerFactory.getLogger(SystemRegistry.class);

    /**
     * {@code adapter} (whoami) exists for the systems with user credentials; {@code exchanger} for token-exchange and
     * {@code serviceAccount} for service-account, and each of the three is null where it does not apply. {@code etag} is
     * the revision of the stored definition.
     */
    public record ConfiguredSystem(String id, BrokerProperties.SystemConfig config, SystemAdapter adapter,
            TokenExchanger exchanger, ServiceAccountSource serviceAccount, String etag) {

        public ConfiguredSystem(String id, BrokerProperties.SystemConfig config, SystemAdapter adapter) {
            this(id, config, adapter, null, null, null);
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

    private final SystemRepository repository;
    private final SystemAdapters adapters;
    private volatile Map<String, ConfiguredSystem> systems = Map.of();

    public SystemRegistry(SystemRepository repository, SystemAdapters adapters) {
        this.repository = repository;
        this.adapters = adapters;
        reload();
    }

    /**
     * Reads the table and swaps the snapshot. A row that cannot be turned into a system (it was written by something other
     * than the admin API) is left out and logged, so it cannot take the others down. A database error propagates and the
     * previous snapshot stays.
     */
    public synchronized void reload() {
        Map<String, ConfiguredSystem> previous = systems;
        Map<String, ConfiguredSystem> next = new LinkedHashMap<>();
        for (SystemDefinition definition : repository.findAll()) {
            ConfiguredSystem kept = previous.get(definition.id());
            if (kept != null && kept.etag().equals(definition.etag())) {
                next.put(definition.id(), kept);
                continue;
            }
            try {
                next.put(definition.id(), adapters.build(definition));
            } catch (RuntimeException e) {
                log.error("System {} is stored but cannot be served: {}", definition.id(), e.getMessage());
            }
        }
        if (!next.keySet().equals(previous.keySet()) || next.entrySet().stream()
                .anyMatch(entry -> previous.get(entry.getKey()) != entry.getValue())) {
            log.info("Systems loaded: {}", next.keySet());
        }
        systems = Map.copyOf(next);
    }

    public Optional<ConfiguredSystem> find(String id) {
        return Optional.ofNullable(systems.get(id));
    }

    public List<ConfiguredSystem> all() {
        return systems.values().stream().sorted(java.util.Comparator.comparing(ConfiguredSystem::id)).toList();
    }
}
