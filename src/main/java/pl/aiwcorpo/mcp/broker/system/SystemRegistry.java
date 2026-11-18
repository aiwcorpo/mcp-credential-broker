package pl.aiwcorpo.mcp.broker.system;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;

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
     * the revision of the stored definition and {@code clientRevision} the one that grants are issued under; {@code displayName} is what the administrator
     * named the system, or null.
     */
    public record ConfiguredSystem(String id, BrokerProperties.SystemConfig config, SystemAdapter adapter,
            TokenExchanger exchanger, ServiceAccountSource serviceAccount, String etag, String clientRevision,
            String displayName) {

        public ConfiguredSystem(String id, BrokerProperties.SystemConfig config, SystemAdapter adapter, TokenExchanger exchanger,
                ServiceAccountSource serviceAccount, String etag, String clientRevision) {
            this(id, config, adapter, exchanger, serviceAccount, etag, clientRevision, null);
        }

        public ConfiguredSystem(String id, BrokerProperties.SystemConfig config, SystemAdapter adapter) {
            this(id, config, adapter, null, null, null, null, null);
        }

        /** Whether a user secret is checked with a whoami when it is stored (everywhere but a generic-rest system without one). */
        public boolean verifiesUserSecrets() {
            return !(adapter instanceof GenericRestAdapter generic) || generic.hasWhoami();
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
    private final Clock clock;
    private final Duration maxAge;
    private volatile Map<String, ConfiguredSystem> systems = Map.of();
    private volatile Instant loadedAt;

    /** @param maxAge how old the snapshot may get before {@link #requireRecentLoad()} refuses it */
    public SystemRegistry(SystemRepository repository, SystemAdapters adapters, Clock clock, Duration maxAge) {
        this.repository = repository;
        this.adapters = adapters;
        this.clock = clock;
        this.maxAge = maxAge;
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
        loadedAt = clock.instant();
    }

    /**
     * For a resolve that reads no row of its own (token exchange, service account), the snapshot is the only proof that the
     * system still exists in this form; one that has not been reloaded within {@code maxAge} is treated as a database outage.
     */
    public void requireRecentLoad() {
        if (clock.instant().isAfter(loadedAt.plus(maxAge))) {
            throw new DataAccessResourceFailureException("systems not reloaded within " + maxAge);
        }
    }

    public Optional<ConfiguredSystem> find(String id) {
        return Optional.ofNullable(systems.get(id));
    }

    public List<ConfiguredSystem> all() {
        return systems.values().stream().sorted(java.util.Comparator.comparing(ConfiguredSystem::id)).toList();
    }
}
