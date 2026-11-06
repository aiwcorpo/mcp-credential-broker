package pl.aiwcorpo.mcp.broker.credential;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.RecoverableDataAccessException;
import org.springframework.dao.TransientDataAccessException;
import org.springframework.transaction.TransactionException;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.InternalJwtClaims;
import pl.aiwcorpo.mcp.broker.auth.KeySourceUnavailableException;
import pl.aiwcorpo.mcp.broker.auth.SubjectTokenVerifier;
import pl.aiwcorpo.mcp.broker.auth.TokenRejectedException;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import pl.aiwcorpo.mcp.broker.secret.StoredCredential;
import pl.aiwcorpo.mcp.broker.system.BackendIdentity;
import pl.aiwcorpo.mcp.broker.system.ExchangeDeniedException;
import pl.aiwcorpo.mcp.broker.system.SystemIds;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry.ConfiguredSystem;
import pl.aiwcorpo.mcp.broker.system.TokenExchanger;
import pl.aiwcorpo.mcp.broker.system.UpstreamUnavailableException;
import pl.aiwcorpo.mcp.broker.system.WhoamiResult;

/**
 * Resolve (gateway) for all four credential types and PUT secret (portal BFF) for user-secret credentials. The user
 * is always the authenticated caller; no method takes a sub from the request.
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
    private final SubjectTokenVerifier subjectTokens;
    private final LostSecretSignal lostSecrets;

    public CredentialService(SystemRegistry systems, ConnectionRepository connections, SecretStore secrets,
            InvalidationPublisher invalidations, OAuthService oauth, SubjectTokenVerifier subjectTokens, AuditLog audit,
            Clock clock, int cacheTtlSeconds, Duration expiringThreshold, LostSecretSignal lostSecrets) {
        this.lostSecrets = lostSecrets;
        this.subjectTokens = subjectTokens;
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
                .gatewayContext(user.tool(), user.prv())
                .system(systemId);
        try {
            ConfiguredSystem system = systems.find(systemId).orElseThrow(() -> SystemIds.isValid(systemId)
                    ? new SystemNotConfiguredException(systemId)
                    : new InvalidRequestException("unknown system"));
            if (scopes != null && new HashSet<>(scopes).size() != scopes.size()) {
                throw new InvalidRequestException("scopes must be unique");
            }
            if (subjectToken != null && !system.supports(CredentialType.TOKEN_EXCHANGE)) {
                // A user token sent where none is needed is a gateway bug; accepting it silently would
                // hide that the gateway hands user tokens to places that do not need them.
                throw new InvalidRequestException("subjectToken is only for token-exchange systems");
            }
            Resolved resolved;
            if (system.supports(CredentialType.TOKEN_EXCHANGE)) {
                entry.credentialType(CredentialType.TOKEN_EXCHANGE.wire());
                resolved = exchange(system, user.sub(), subjectToken);
            } else if (system.supports(CredentialType.SERVICE_ACCOUNT)) {
                entry.credentialType(CredentialType.SERVICE_ACCOUNT.wire());
                resolved = serviceAccount(system);
            } else {
                resolved = userCredential(caller, system, entry);
            }
            entry.ok("resolved");
            return resolved;
        } catch (CredentialRequiredException e) {
            entry.denied("credential_required", "credential_required");
            throw e;
        } catch (SubjectTokenInvalidException e) {
            entry.denied("subject_token_invalid", null);
            throw e;
        } catch (InvalidRequestException e) {
            entry.denied("invalid_request", "invalid_argument");
            throw e;
        } catch (ExchangeDeniedException e) {
            entry.denied("exchange_denied", "access_denied");
            throw e;
        } catch (SystemNotConfiguredException e) {
            log.error("Resolve for a system without configuration in the broker: {}", systemId);
            entry.error("system_not_configured", "internal_error");
            throw e;
        } catch (UpstreamUnavailableException e) {
            entry.error("provider_unavailable", "upstream_unavailable");
            throw e;
        } catch (SecretStoreUnavailableException e) {
            entry.error("secret_store_unavailable", "upstream_unavailable");
            throw e;
        } catch (RuntimeException e) {
            entry.error(unavailableDatabase(e) ? "database_unavailable" : "internal_error", "upstream_unavailable");
            throw e;
        }
    }

    private Resolved userCredential(Caller.Gateway caller, ConfiguredSystem system, AuditLog.Entry entry) {
        InternalJwtClaims user = caller.claims();
        Instant now = clock.instant();
        Optional<Connection> connection = connections.find(user.sub(), system.id());
        if (connection.isEmpty() || !connection.get().status(now, expiringThreshold).usable()) {
            throw new CredentialRequiredException(system.id());
        }
        Connection found = connection.get();
        Optional<StoredCredential> read = secrets.get(found.secretKey());
        if (read.isEmpty()) {
            // A refresh or a new PUT may have switched the row to a newer version and deleted this one between the two reads.
            Optional<Connection> again = connections.find(user.sub(), system.id());
            if (again.isPresent() && !Objects.equals(again.get().secretVersion(), found.secretVersion())
                    && again.get().status(now, expiringThreshold).usable()) {
                found = again.get();
                read = secrets.get(found.secretKey());
            }
        }
        entry.credentialType(found.type().wire());
        if (read.isEmpty()) {
            lostSecrets.seen(system.id(), LostSecretSignal.Place.RESOLVE);
            if (lostSecrets.mayMark() && store.markSecretMissing(found)) {
                audit.event("connection_change", caller.requestId()).user(found.sub(), null, null).system(found.system())
                        .credentialType(found.type().wire()).backendUser(found.backendUser()).error("secret_missing", null);
            }
            throw new CredentialRequiredException(system.id());
        }
        StoredCredential stored = read.get();
        if (!system.supports(found.type())) {
            // The system no longer takes this kind of credential (its types were changed through the admin API).
            throw new CredentialRequiredException(system.id());
        }
        if (found.type() == CredentialType.USER_SECRET && stored.isBasic() != system.config().userSecretIsBasic()) {
            // The system was reconfigured after the user connected: the kept value would go out in the wrong header.
            throw new CredentialRequiredException(system.id());
        }
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
        CredentialScheme scheme = found.type() == CredentialType.USER_SECRET ? userSecretScheme(system) : system.config().secretScheme();
        return new Resolved(scheme, stored.value(), found.type(), expiry, ttl(clock.instant(), expiry));
    }

    /** Nothing is stored: the token lives in the response and in the gateway's cache for at most cacheTtlSeconds. */
    private Resolved exchange(ConfiguredSystem system, String sub, String subjectToken) {
        if (subjectToken == null) {
            throw new InvalidRequestException("subjectToken is required for this system");
        }
        try {
            subjectTokens.verify(subjectToken, sub);
        } catch (TokenRejectedException e) {
            log.info("subjectToken refused: {}", e.reason());
            throw new SubjectTokenInvalidException();
        } catch (KeySourceUnavailableException e) {
            throw new UpstreamUnavailableException(e.getMessage());
        }
        TokenExchanger.ExchangedToken token = system.tokenExchanger()
                .orElseThrow(() -> new IllegalStateException("token-exchange system without an exchanger"))
                .exchange(SecretValue.of(subjectToken));
        return new Resolved(CredentialScheme.BEARER, token.accessToken(), CredentialType.TOKEN_EXCHANGE, token.expiresAt(),
                ttl(clock.instant(), token.expiresAt()));
    }

    private Resolved serviceAccount(ConfiguredSystem system) {
        ServiceAccountKeys.Key key = system.serviceAccountSource()
                .orElseThrow(() -> new IllegalStateException("service-account system without a key source"))
                .key();
        return new Resolved(system.config().secretScheme(), key.value(), CredentialType.SERVICE_ACCOUNT, key.expiresAt(),
                ttl(clock.instant(), key.expiresAt()));
    }

    public Stored putSecret(Caller.PortalUser caller, String systemId, SecretValue secret, String expiresAtText) {
        return putSecret(caller, systemId, null, secret, expiresAtText);
    }

    /** @param username login for a system whose user secret is a Basic pair (CC-222), null for a single token */
    public Stored putSecret(Caller.PortalUser caller, String systemId, String username, SecretValue secret, String expiresAtText) {
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
            SecretValue kept = userSecretValue(system, username, secret);
            CredentialScheme scheme = userSecretScheme(system);
            BackendIdentity identity = switch (system.adapter().whoami(scheme, kept)) {
                case WhoamiResult.Rejected rejected -> throw new SecretRejectedException("secret_invalid");
                case WhoamiResult.Identified identified -> identified.identity();
            };
            entry.backendUser(identity.username());

            Instant expires = expiresAt == null ? null : expiresAt.truncatedTo(ChronoUnit.SECONDS);
            Replaced replaced = oauth.underWriteLock(caller.sub(), system.id(), () -> {
                Optional<Connection> previous = connections.find(caller.sub(), system.id());
                StoredCredential oldGrant = previous.map(oauth::grantToRevoke).orElse(null);
                Connection written = store.replace(
                        new Connection(caller.sub(), system.id(), CredentialType.USER_SECRET, Connection.StoredState.CONNECTED,
                                identity.username(), expires, now.truncatedTo(ChronoUnit.SECONDS), null, null, null),
                        StoredCredential.userSecret(kept, system.config().userSecretIsBasic() ? CredentialScheme.BASIC : null), previous, true);
                boolean revoked = oauth.revokeReplacedGrant(system.id(), oldGrant);
                if (previous.isPresent() && oauth.holdsGrant(previous.get()) && (oldGrant == null || !revoked)) {
                    oauth.auditReplacedGrantNotRevoked(caller.requestId(), caller.sub(), system.id());
                }
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
        } catch (UserBeingOffboardedException e) {
            entry.denied("user_offboarding", "upstream_unavailable");
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

    private static CredentialScheme userSecretScheme(ConfiguredSystem system) {
        return system.config().effectiveUserSecretScheme();
    }

    /**
     * What the secret store keeps for a user secret: the token as given, or for a Basic system the base64 of
     * {@code username:secret}, which is also the value resolve returns. The username and the password are not kept apart.
     */
    private static SecretValue userSecretValue(ConfiguredSystem system, String username, SecretValue secret) {
        if (!system.config().userSecretIsBasic()) {
            if (username != null) {
                throw new InvalidRequestException("username is only for systems with a Basic user secret");
            }
            return secret;
        }
        if (username == null || username.isEmpty() || username.contains(":")) {
            throw new InvalidRequestException("a Basic user secret needs a username without a colon");
        }
        String login = username + ":" + secret.reveal();
        return SecretValue.of(Base64.getEncoder().encodeToString(login.getBytes(StandardCharsets.UTF_8)));
    }

    private record Replaced(Connection connection, Optional<Connection> previous) {
    }

    /** Connections of the calling user with their C4 status; never touches the secret store. */
    public List<Listed> connections(Caller.PortalUser caller) {
        Instant now = clock.instant();
        return connections.findAll(caller.sub()).stream()
                .map(c -> new Listed(c, systems.find(c.system()).filter(s -> s.supports(c.type())).isPresent()
                        ? c.status(now, expiringThreshold) : ConnectionStatus.ERROR))
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
            if (!SystemIds.isValid(systemId)) {
                throw new InvalidRequestException("unknown system");
            }
            return oauth.underDisconnectLock(caller.sub(), systemId, () -> {
                Optional<Connection> existing = connections.find(caller.sub(), systemId);
                if (existing.isEmpty()) {
                    entry.ok("nothing_to_disconnect");
                    return false;
                }
                entry.credentialType(existing.get().type().wire()).backendUser(existing.get().backendUser());
                if (!oauth.revokeAtProvider(existing.get())) {
                    audit.event("connection_change", caller.requestId())
                            .user(caller.sub(), caller.username(), caller.azp())
                            .system(systemId)
                            .credentialType(existing.get().type().wire())
                            .error("provider_revoke_failed", null);
                }
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

    public static boolean unavailableDatabase(RuntimeException e) {
        return e instanceof DataAccessResourceFailureException || e instanceof TransientDataAccessException
                || e instanceof RecoverableDataAccessException || e instanceof TransactionException;
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
