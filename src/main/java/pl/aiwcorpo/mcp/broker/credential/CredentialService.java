package pl.aiwcorpo.mcp.broker.credential;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.InternalJwtClaims;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
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

    private final SystemRegistry systems;
    private final ConnectionRepository connections;
    private final SecretStore secrets;
    private final InvalidationPublisher invalidations;
    private final AuditLog audit;
    private final Clock clock;
    private final int cacheTtlSeconds;
    private final Duration expiringThreshold;

    public CredentialService(SystemRegistry systems, ConnectionRepository connections, SecretStore secrets,
            InvalidationPublisher invalidations, AuditLog audit, Clock clock, int cacheTtlSeconds, Duration expiringThreshold) {
        this.systems = systems;
        this.connections = connections;
        this.secrets = secrets;
        this.invalidations = invalidations;
        this.audit = audit;
        this.clock = clock;
        this.cacheTtlSeconds = cacheTtlSeconds;
        this.expiringThreshold = expiringThreshold;
    }

    public Resolved resolve(Caller.Gateway caller, String systemId) {
        InternalJwtClaims user = caller.claims();
        AuditLog.Entry entry = audit.event("credential_resolve", caller.requestId())
                .user(user.sub(), user.usr(), user.azp())
                .gatewayContext(user.vs(), user.tool(), user.prv())
                .system(systemId);
        try {
            ConfiguredSystem system = systems.find(systemId)
                    .orElseThrow(() -> new InvalidRequestException("system is not configured in the broker"));
            Instant now = clock.instant();
            Optional<Connection> connection = connections.find(user.sub(), system.id());
            if (connection.isEmpty() || !connection.get().status(now, expiringThreshold).usable()) {
                throw new CredentialRequiredException(system.id());
            }
            Connection found = connection.get();
            entry.credentialType(found.type().wire());
            StoredCredential stored = secrets.get(new SecretKey(user.sub(), system.id()))
                    .orElseThrow(() -> {
                        log.warn("Connection metadata without a stored secret for system {}", system.id());
                        return new CredentialRequiredException(system.id());
                    });
            if (stored.type() != found.type()) {
                throw new SecretStoreUnavailableException("stored credential type differs from connection metadata");
            }
            connections.touch(user.sub(), system.id(), now);
            Resolved resolved = new Resolved(system.config().secretScheme(), stored.value(), found.type(),
                    found.expiresAt(), ttl(now, found.expiresAt()));
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
            entry.error("internal_error", "internal_error");
            throw e;
        }
    }

    public Stored putSecret(Caller.PortalUser caller, String systemId, SecretValue secret, Instant expiresAt) {
        AuditLog.Entry entry = audit.event("connection_change", caller.requestId())
                .user(caller.sub(), caller.username(), caller.azp())
                .system(systemId)
                .credentialType(CredentialType.USER_SECRET.wire());
        try {
            ConfiguredSystem system = systems.find(systemId)
                    .filter(s -> s.supports(CredentialType.USER_SECRET))
                    .orElseThrow(() -> new InvalidRequestException("system does not accept user secrets"));
            Instant now = clock.instant();
            if (expiresAt != null && !expiresAt.isAfter(now)) {
                throw new InvalidRequestException("expiresAt is in the past");
            }
            BackendIdentity identity = switch (system.adapter().whoami(system.config().secretScheme(), secret)) {
                case WhoamiResult.Rejected rejected -> throw new SecretRejectedException("secret_invalid");
                case WhoamiResult.Identified identified -> identified.identity();
            };
            if (!sameIdentity(caller, system, identity)) {
                throw new SecretRejectedException("identity_mismatch");
            }

            SecretKey key = new SecretKey(caller.sub(), system.id());
            boolean replaced = connections.find(caller.sub(), system.id()).isPresent();
            secrets.put(key, StoredCredential.of(CredentialType.USER_SECRET, secret));
            Instant expires = expiresAt == null ? null : expiresAt.truncatedTo(ChronoUnit.SECONDS);
            Connection connection = new Connection(caller.sub(), system.id(), CredentialType.USER_SECRET,
                    Connection.StoredState.CONNECTED, identity.username(), expires, now.truncatedTo(ChronoUnit.SECONDS), null);
            try {
                connections.upsert(connection, now);
            } catch (RuntimeException e) {
                // Without metadata the secret is unreachable but still stored; remove it so a failed
                // request leaves nothing behind.
                deleteQuietly(key);
                throw e;
            }
            if (replaced) {
                invalidations.invalidated(caller.sub(), system.id());
            }
            Stored stored = new Stored(connection.status(now, expiringThreshold), identity.username(), expires);
            entry.ok(replaced ? "secret_replaced" : "secret_stored");
            return stored;
        } catch (SecretRejectedException e) {
            entry.denied(e.error(), null);
            throw e;
        } catch (InvalidRequestException e) {
            entry.denied("invalid_request", "invalid_argument");
            throw e;
        } catch (SecretStoreUnavailableException | UpstreamUnavailableException e) {
            entry.error(e instanceof UpstreamUnavailableException ? "system_unavailable" : "secret_store_unavailable",
                    "upstream_unavailable");
            throw e;
        } catch (RuntimeException e) {
            entry.error("internal_error", "internal_error");
            throw e;
        }
    }

    /** C4.1: the backend account must be the SSO user's own (case-insensitive, as Jira user names are). */
    static boolean sameIdentity(Caller.PortalUser caller, ConfiguredSystem system, BackendIdentity identity) {
        String claim = system.config().identityClaim();
        String expected = caller.identity(claim);
        String actual = "email".equals(claim) ? identity.email() : identity.username();
        return expected != null && actual != null
                && expected.toLowerCase(Locale.ROOT).equals(actual.toLowerCase(Locale.ROOT));
    }

    private int ttl(Instant now, Instant expiresAt) {
        if (expiresAt == null) {
            return cacheTtlSeconds;
        }
        long remaining = Duration.between(now, expiresAt).toSeconds();
        return (int) Math.max(0, Math.min(cacheTtlSeconds, remaining));
    }

    private void deleteQuietly(SecretKey key) {
        try {
            secrets.delete(key);
        } catch (RuntimeException e) {
            log.error("Secret for system {} stored without metadata and could not be removed ({})", key.system(),
                    e.getClass().getSimpleName());
        }
    }
}
