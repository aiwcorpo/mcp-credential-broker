package pl.aiwcorpo.mcp.broker.credential;

import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.RecoverableDataAccessException;
import org.springframework.dao.TransientDataAccessException;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.InternalJwtClaims;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import pl.aiwcorpo.mcp.broker.secret.StoredCredential;
import pl.aiwcorpo.mcp.broker.system.BackendIdentity;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry.ConfiguredSystem;
import pl.aiwcorpo.mcp.broker.system.UpstreamUnavailableException;
import pl.aiwcorpo.mcp.broker.system.WhoamiResult;

/**
 * Resolve (gateway) and PUT secret (portal BFF) for user-secret credentials. The user is always the
 * authenticated caller; no method takes a sub from the request.
 */
public class CredentialService {

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);

    public record Resolved(CredentialScheme scheme, SecretValue value, CredentialType type, Instant expiresAt,
            int cacheTtlSeconds) {

        @Override
        public String toString() {
            return "Resolved[scheme=" + scheme + ", type=" + type + ", expiresAt=" + expiresAt + "]";
        }
    }

    public record Stored(ConnectionStatus status, String backendUser, Instant expiresAt) {
    }

    /** lastUsedAt is informational; writing it on every resolve would put a database write on the hot path. */
    static final Duration LAST_USED_PRECISION = Duration.ofMinutes(5);

    private final SystemRegistry systems;
    private final ConnectionRepository connections;
    private final SecretStore secrets;
    private final InvalidationPublisher invalidations;
    private final ConnectionStore store;
    private final OAuthService oauth;
    private final AuditLog audit;
    private final Clock clock;
    private final int cacheTtlSeconds;
    private final Duration expiringThreshold;

    public CredentialService(SystemRegistry systems, ConnectionRepository connections, SecretStore secrets,
            InvalidationPublisher invalidations, OAuthService oauth, AuditLog audit, Clock clock, int cacheTtlSeconds,
            Duration expiringThreshold) {
        this.systems = systems;
        this.connections = connections;
        this.secrets = secrets;
        this.invalidations = invalidations;
        this.store = new ConnectionStore(connections, secrets, invalidations, clock);
        this.oauth = oauth;
        this.audit = audit;
        this.clock = clock;
        this.cacheTtlSeconds = cacheTtlSeconds;
        this.expiringThreshold = expiringThreshold;
    }

    public Resolved resolve(Caller.Gateway caller, String systemId, List<String> scopes, String subjectToken) {
        InternalJwtClaims user = caller.claims();
        AuditLog.Entry entry = audit.event("credential_resolve", caller.requestId())
                .user(user.sub(), user.usr(), user.azp())
                .gatewayContext(user.vs(), user.tool(), user.prv())
                .system(systemId);
        try {
            ConfiguredSystem system = systems.find(systemId)
                    .orElseThrow(() -> new InvalidRequestException("system is not configured in the broker"));
            if (scopes != null && new HashSet<>(scopes).size() != scopes.size()) {
                throw new InvalidRequestException("scopes must be unique");
            }
            if (subjectToken != null && !system.supports(CredentialType.TOKEN_EXCHANGE)) {
                // A user token sent where none is needed is a gateway bug; accepting it silently would
                // hide that the gateway hands user tokens to places that do not need them.
                throw new InvalidRequestException("subjectToken is only for token-exchange systems");
            }
            Instant now = clock.instant();
            Optional<Connection> connection = connections.find(user.sub(), system.id());
            if (connection.isEmpty() || !connection.get().status(now, expiringThreshold).usable()) {
                throw new CredentialRequiredException(system.id());
            }
            Connection found = connection.get();
            entry.credentialType(found.type().wire());
            StoredCredential stored = secrets.get(found.secretKey())
                    .orElseThrow(() -> {
                        log.warn("Connection metadata without a stored secret for system {}", system.id());
                        return new CredentialRequiredException(system.id());
                    });
            if (stored.type() != found.type()) {
                throw new SecretStoreUnavailableException("stored credential type differs from connection metadata");
            }
            if (found.type() == CredentialType.USER_OAUTH) {
                OAuthService.Fresh fresh = oauth.ensureFresh(caller.requestId(), found, stored);
                found = fresh.connection();
                stored = fresh.credential();
            }
            if (found.lastUsedAt() == null || found.lastUsedAt().isBefore(now.minus(LAST_USED_PRECISION))) {
                connections.touch(user.sub(), system.id(), now);
            }
            Instant expiry = found.type() == CredentialType.USER_OAUTH ? found.accessExpiresAt() : found.expiresAt();
            Resolved resolved = new Resolved(system.config().secretScheme(), stored.value(), found.type(),
                    expiry, ttl(clock.instant(), expiry));
            entry.ok("resolved");
            return resolved;
        } catch (CredentialRequiredException e) {
            entry.denied("credential_required", "credential_required");
            throw e;
        } catch (InvalidRequestException e) {
            entry.denied("invalid_request", "invalid_argument");
            throw e;
        } catch (SecretStoreUnavailableException | UpstreamUnavailableException e) {
            entry.error("secret_store_unavailable", "upstream_unavailable");
            throw e;
        } catch (RuntimeException e) {
            entry.error(unavailableDatabase(e) ? "database_unavailable" : "internal_error", "upstream_unavailable");
            throw e;
        }
    }

    public Stored putSecret(Caller.PortalUser caller, String systemId, SecretValue secret, String expiresAtText) {
        AuditLog.Entry entry = audit.event("connection_change", caller.requestId())
                .user(caller.sub(), caller.username(), caller.azp())
                .system(systemId)
                .credentialType(CredentialType.USER_SECRET.wire());
        try {
            ConfiguredSystem system = systems.find(systemId)
                    .filter(s -> s.supports(CredentialType.USER_SECRET))
                    .orElseThrow(() -> new InvalidRequestException("system does not accept user secrets"));
            Instant now = clock.instant();
            Instant expiresAt = parseTimestamp(expiresAtText);
            BackendIdentity identity = switch (system.adapter().whoami(system.config().secretScheme(), secret)) {
                case WhoamiResult.Rejected rejected -> throw new SecretRejectedException("secret_invalid");
                case WhoamiResult.Identified identified -> identified.identity();
            };
            if (!IdentityRule.matches(system.config().identityClaim(), caller.claims(), identity)) {
                throw new SecretRejectedException("identity_mismatch");
            }

            Instant expires = expiresAt == null ? null : expiresAt.truncatedTo(ChronoUnit.SECONDS);
            Replaced replaced = oauth.underRefreshLock(caller.sub(), system.id(), () -> {
                Optional<Connection> previous = connections.find(caller.sub(), system.id());
                StoredCredential oldGrant = previous.map(oauth::grantToRevoke).orElse(null);
                Connection written = store.replace(
                        new Connection(caller.sub(), system.id(), CredentialType.USER_SECRET, Connection.StoredState.CONNECTED,
                                identity.username(), expires, now.truncatedTo(ChronoUnit.SECONDS), null, null, null),
                        StoredCredential.of(CredentialType.USER_SECRET, secret), previous, true);
                oauth.revokeReplacedGrant(system.id(), oldGrant);
                return new Replaced(written, previous);
            });
            Optional<Connection> previous = replaced.previous();
            Stored stored = new Stored(replaced.connection().status(now, expiringThreshold), identity.username(), expires);
            entry.ok(previous.isPresent() ? "secret_replaced" : "secret_stored");
            return stored;
        } catch (SecretRejectedException e) {
            entry.denied(e.reason(), null);
            throw e;
        } catch (InvalidRequestException e) {
            entry.denied("invalid_request", "invalid_argument");
            throw e;
        } catch (SecretStoreUnavailableException | UpstreamUnavailableException e) {
            entry.error(e instanceof UpstreamUnavailableException ? "system_unavailable" : "secret_store_unavailable",
                    "upstream_unavailable");
            throw e;
        } catch (RuntimeException e) {
            entry.error(unavailableDatabase(e) ? "database_unavailable" : "internal_error", "upstream_unavailable");
            throw e;
        }
    }

    private record Replaced(Connection connection, Optional<Connection> previous) {
    }

    /** Connections of the calling user with their C4 status; never touches the secret store. */
    public List<Listed> connections(Caller.PortalUser caller) {
        Instant now = clock.instant();
        return connections.findAll(caller.sub()).stream()
                .map(c -> new Listed(c, c.status(now, expiringThreshold)))
                .toList();
    }

    public record Listed(Connection connection, ConnectionStatus status) {
    }

    /**
     * Disconnects the calling user's system. Idempotent. The secret goes first (all KV versions), then the
     * row: if the store fails, the connection stays usable and the call can be repeated; if the row delete
     * fails after that, resolve already answers credential_required. The tokens of a user-oauth connection are
     * revoked at the provider first, best effort; a user-secret PAT is revoked by its owner in the system.
     */
    public boolean disconnect(Caller.PortalUser caller, String systemId) {
        AuditLog.Entry entry = audit.event("connection_change", caller.requestId())
                .user(caller.sub(), caller.username(), caller.azp())
                .system(systemId);
        try {
            if (!SystemRegistry.KNOWN_SYSTEMS.contains(systemId)) {
                throw new InvalidRequestException("unknown system");
            }
            return oauth.underRefreshLock(caller.sub(), systemId, () -> {
                Optional<Connection> existing = connections.find(caller.sub(), systemId);
                if (existing.isEmpty()) {
                    entry.ok("nothing_to_disconnect");
                    return false;
                }
                entry.credentialType(existing.get().type().wire());
                oauth.revokeAtProvider(existing.get());
                secrets.delete(existing.get().secretKey());
                connections.delete(caller.sub(), systemId);
                invalidations.invalidated(caller.sub(), systemId);
                entry.ok("disconnected");
                return true;
            });
        } catch (InvalidRequestException e) {
            entry.denied("invalid_request", "invalid_argument");
            throw e;
        } catch (SecretStoreUnavailableException | UpstreamUnavailableException e) {
            entry.error(e instanceof UpstreamUnavailableException ? "connection_busy" : "secret_store_unavailable",
                    "upstream_unavailable");
            throw e;
        } catch (RuntimeException e) {
            entry.error(unavailableDatabase(e) ? "database_unavailable" : "internal_error", "upstream_unavailable");
            throw e;
        }
    }

    static boolean unavailableDatabase(RuntimeException e) {
        return e instanceof DataAccessResourceFailureException || e instanceof TransientDataAccessException
                || e instanceof RecoverableDataAccessException;
    }

    private static Instant parseTimestamp(String value) {
        if (value == null) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeException e) {
            throw new InvalidRequestException("expiresAt is not a valid timestamp");
        }
    }

    private int ttl(Instant now, Instant expiresAt) {
        if (expiresAt == null) {
            return cacheTtlSeconds;
        }
        long remaining = Duration.between(now, expiresAt).toSeconds();
        return (int) Math.max(0, Math.min(cacheTtlSeconds, remaining));
    }
}
