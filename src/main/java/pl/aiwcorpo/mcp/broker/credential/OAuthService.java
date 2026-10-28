package pl.aiwcorpo.mcp.broker.credential;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.broker.api.ReturnPath;
import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.RequestIds;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.oauth.OAuthFlowStore;
import pl.aiwcorpo.mcp.broker.oauth.RefreshLock;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import pl.aiwcorpo.mcp.broker.secret.StoredCredential;
import pl.aiwcorpo.mcp.broker.system.BackendIdentity;
import pl.aiwcorpo.mcp.broker.system.OAuthGrantRejectedException;
import pl.aiwcorpo.mcp.broker.system.OAuthProvider;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry.ConfiguredSystem;
import pl.aiwcorpo.mcp.broker.system.TokenSet;
import pl.aiwcorpo.mcp.broker.system.UpstreamUnavailableException;
import pl.aiwcorpo.mcp.broker.system.WhoamiResult;

/**
 * The user-oauth credential type (C4.2): the authorization code flow with PKCE started and completed for the
 * portal user, and the renewal of access tokens. The user is always the authenticated caller. A flow belongs
 * to the {@code sub} that started it; whoever completes it must present the same {@code sub} and the flow's
 * {@code state}. The account the provider names for the tokens is recorded and shown, not compared with the SSO
 * identity: logins differ between systems for the same person (decision of 2026-10-28).
 */
public class OAuthService {

    private static final Logger log = LoggerFactory.getLogger(OAuthService.class);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int SWEEP_BATCH = 100;

    public record Started(URI authorizeUrl, String flowId) {

        @Override
        public String toString() {
            return "Started[flowId=" + flowId + "]";
        }
    }

    public record Completed(ConnectionStatus status, String backendUser) {
    }

    /** A connection with the credential to hand out, after renewal if it was due. */
    public record Fresh(Connection connection, StoredCredential credential) {
    }

    private final SystemRegistry systems;
    private final ConnectionRepository connections;
    private final SecretStore secrets;
    private final ConnectionStore store;
    private final OAuthFlowStore flows;
    private final RefreshLock lock;
    private final AuditLog audit;
    private final Clock clock;
    private final URI redirectUri;
    private final BrokerProperties.OAuthFlow settings;

    public OAuthService(SystemRegistry systems, ConnectionRepository connections, SecretStore secrets,
            ConnectionStore store, OAuthFlowStore flows, RefreshLock lock, AuditLog audit, Clock clock,
            URI redirectUri, BrokerProperties.OAuthFlow settings) {
        this.systems = systems;
        this.connections = connections;
        this.secrets = secrets;
        this.store = store;
        this.flows = flows;
        this.lock = lock;
        this.audit = audit;
        this.clock = clock;
        this.redirectUri = redirectUri;
        this.settings = settings;
    }

    public Started start(Caller.PortalUser caller, String systemId, String returnPath) {
        AuditLog.Entry entry = portalEntry(caller, systemId);
        try {
            ConfiguredSystem system = oauthSystem(systemId);
            if (!ReturnPath.isValid(returnPath)) {
                throw new InvalidRequestException("returnPath is not a path of the portal");
            }
            String flowId = "flow-" + randomToken(16);
            String state = randomToken(32);
            SecretValue verifier = SecretValue.of(randomToken(32));
            flows.start(new OAuthFlowStore.Flow(flowId, caller.sub(), system.id(), state, verifier), settings.flowTtl());
            URI authorizeUrl = system.oauth().orElseThrow().authorizeUrl(state, challenge(verifier), redirectUri,
                    system.config().oauthScopes().stream().distinct().toList());
            entry.ok("oauth_started");
            return new Started(authorizeUrl, flowId);
        } catch (InvalidRequestException e) {
            entry.denied("invalid_request", "invalid_argument");
            throw e;
        } catch (SecretStoreUnavailableException e) {
            entry.error("flow_store_unavailable", "upstream_unavailable");
            throw e;
        } catch (RuntimeException e) {
            entry.error("internal_error", "upstream_unavailable");
            throw e;
        }
    }

    public Completed complete(Caller.PortalUser caller, String systemId, String flowId, SecretValue code, String state) {
        AuditLog.Entry entry = portalEntry(caller, systemId);
        TokenSet tokens = null;
        OAuthProvider provider = null;
        boolean stored = false;
        try {
            ConfiguredSystem system = oauthSystem(systemId);
            provider = system.oauth().orElseThrow();
            OAuthFlowStore.Flow pending = flows.peek(flowId).orElseThrow(() -> new SecretRejectedException("flow_invalid"));
            if (!pending.sub().equals(caller.sub())) {
                // Not consumed: someone else's request must not be able to burn the owner's flow.
                throw new SecretRejectedException("flow_invalid", "flow_of_another_user");
            }
            if (!pending.system().equals(system.id()) || !constantTimeEquals(pending.state(), state)) {
                // Not consumed either: a callback with a wrong state is not the owner finishing the flow.
                throw new SecretRejectedException("flow_invalid", "state_mismatch");
            }
            OAuthFlowStore.Flow flow = flows.take(flowId).orElseThrow(() -> new SecretRejectedException("flow_invalid"));
            try {
                tokens = provider.exchangeCode(code, flow.codeVerifier(), redirectUri);
            } catch (OAuthGrantRejectedException e) {
                throw new SecretRejectedException("flow_invalid", "code_rejected");
            }
            BackendIdentity identity = switch (system.adapter().whoami(CredentialScheme.BEARER, tokens.accessToken())) {
                case WhoamiResult.Rejected rejected ->
                    throw new UpstreamUnavailableException("provider issued a token that its own whoami refuses");
                case WhoamiResult.Identified identified -> identified.identity();
            };
            TokenSet issued = tokens;
            boolean replaced = underRefreshLock(caller.sub(), system.id(), () -> {
                Instant now = clock.instant();
                Optional<Connection> previous = connections.find(caller.sub(), system.id());
                StoredCredential oldGrant = previous.map(this::grantToRevoke).orElse(null);
                store.replace(
                        new Connection(caller.sub(), system.id(), CredentialType.USER_OAUTH, Connection.StoredState.CONNECTED,
                                identity.username(), null, now.truncatedTo(ChronoUnit.SECONDS), null, null,
                                accessExpiry(issued, now)),
                        new StoredCredential(CredentialType.USER_OAUTH, issued.accessToken(), issued.refreshToken()),
                        previous, true);
                revokeGrantQuietly(system.oauth().orElseThrow(), oldGrant);
                return previous.isPresent();
            });
            stored = true;
            entry.backendUser(identity.username()).ok(replaced ? "oauth_replaced" : "oauth_connected");
            return new Completed(ConnectionStatus.CONNECTED, identity.username());
        } catch (SecretRejectedException e) {
            entry.denied(e.reason(), null);
            throw e;
        } catch (InvalidRequestException e) {
            entry.denied("invalid_request", "invalid_argument");
            throw e;
        } catch (SecretStoreUnavailableException | UpstreamUnavailableException e) {
            entry.error(e instanceof UpstreamUnavailableException ? "provider_unavailable" : "secret_store_unavailable",
                    "upstream_unavailable");
            throw e;
        } catch (RuntimeException e) {
            entry.error(CredentialService.unavailableDatabase(e) ? "database_unavailable" : "internal_error",
                    "upstream_unavailable");
            throw e;
        } finally {
            if (tokens != null && !stored) {
                // Every way out after the exchange that stores nothing leaves live tokens at the provider.
                revokeQuietly(provider, tokens.accessToken());
                revokeQuietly(provider, tokens.refreshToken());
            }
        }
    }

    /**
     * Runs a change of one connection while holding the lock that refreshes take, so a refresh in flight cannot
     * write over it and it cannot interleave with another change. Systems without OAuth need no lock.
     */
    public <T> T underRefreshLock(String sub, String systemId, Supplier<T> action) {
        if (systems.find(systemId).filter(s -> s.oauth().isPresent()).isEmpty()) {
            return action.get();
        }
        String owner = lock.acquire(sub, systemId, settings.refreshLockWait())
                .orElseThrow(() -> new UpstreamUnavailableException("another change of this connection is in progress"));
        try {
            return action.get();
        } finally {
            lock.release(sub, systemId, owner);
        }
    }

    /**
     * Renews the access token when it has less than the refresh margin left, so a token handed to the gateway
     * stays valid for longer than the gateway caches it. Provider failure while the current token still works
     * is not an error for the caller.
     */
    public Fresh ensureFresh(String requestId, Connection found, StoredCredential stored) {
        Instant dueBefore = clock.instant().plus(settings.refreshMargin());
        if (!due(found, dueBefore)) {
            return new Fresh(found, stored);
        }
        return renew(requestId, found.sub(), found.system(), found, stored, settings.refreshMargin());
    }

    /**
     * Background renewal of tokens that will be due within the sweep window. Stops at the first failure of the
     * broker's own stores (renewing more would spend refresh tokens it may not be able to save) and skips the
     * remaining rows of a system whose provider just failed.
     */
    public int refreshDue() {
        List<String> oauthSystems = systems.all().stream().filter(s -> s.oauth().isPresent()).map(ConfiguredSystem::id).toList();
        List<Connection> due = connections.findOAuthExpiringBefore(clock.instant().plus(settings.sweepWindow()), oauthSystems, SWEEP_BATCH);
        Set<String> failedProviders = new HashSet<>();
        int renewed = 0;
        for (Connection connection : due) {
            if (failedProviders.contains(connection.system())) {
                continue;
            }
            try {
                renew(RequestIds.next(clock), connection.sub(), connection.system(), null, null, settings.sweepWindow());
                renewed++;
            } catch (CredentialRequiredException e) {
                log.info("Connection to {} no longer renewable", connection.system());
            } catch (SecretStoreUnavailableException e) {
                log.warn("Token sweep stopped, the secret store or lock is unavailable: {}", e.getMessage());
                break;
            } catch (UpstreamUnavailableException e) {
                failedProviders.add(connection.system());
                log.warn("Token renewal for {} failed: {}", connection.system(), e.getMessage());
            } catch (RuntimeException e) {
                if (CredentialService.unavailableDatabase(e)) {
                    log.warn("Token sweep stopped, the database is unavailable");
                    break;
                }
                log.warn("Token renewal for {} failed ({})", connection.system(), e.getClass().getSimpleName());
            }
        }
        return renewed;
    }

    /** Best effort: the connection is removed locally whether or not the provider could be reached. */
    public void revokeAtProvider(Connection connection) {
        Optional<ConfiguredSystem> system = systems.find(connection.system());
        if (system.isEmpty() || system.get().oauth().isEmpty()) {
            return;
        }
        revokeGrantQuietly(system.get().oauth().get(), grantToRevoke(connection));
    }

    /** The stored tokens of a connected user-oauth connection, or null when there is nothing to revoke or the store fails. */
    StoredCredential grantToRevoke(Connection connection) {
        if (connection.type() != CredentialType.USER_OAUTH || connection.state() != Connection.StoredState.CONNECTED) {
            return null;
        }
        try {
            return secrets.get(connection.secretKey()).orElse(null);
        } catch (SecretStoreUnavailableException e) {
            log.warn("Token for {} not revoked at the provider: {}", connection.system(), e.getMessage());
            return null;
        }
    }

    /** Revokes the tokens of a grant that a new connection has just replaced; the first argument names its system. */
    void revokeReplacedGrant(String systemId, StoredCredential grant) {
        systems.find(systemId).flatMap(ConfiguredSystem::oauth).ifPresent(provider -> revokeGrantQuietly(provider, grant));
    }

    private void revokeGrantQuietly(OAuthProvider provider, StoredCredential grant) {
        if (grant != null) {
            revokeQuietly(provider, grant.refreshToken());
            revokeQuietly(provider, grant.value());
        }
    }

    /** @param window renew when the access token stops working within this time: the margin for a caller, the sweep window for the sweep */
    private Fresh renew(String requestId, String sub, String systemId, Connection seen, StoredCredential seenCredential,
            Duration window) {
        ConfiguredSystem system = systems.find(systemId).orElseThrow(() -> new CredentialRequiredException(systemId));
        OAuthProvider provider = system.oauth().orElseThrow(() -> new CredentialRequiredException(systemId));
        Instant start = clock.instant();
        Optional<String> owner = lock.acquire(sub, systemId, settings.refreshLockWait());
        if (owner.isEmpty()) {
            if (seen != null && seen.accessExpiresAt() != null && seen.accessExpiresAt().isAfter(start)) {
                return new Fresh(seen, seenCredential);
            }
            throw new UpstreamUnavailableException("token renewal is taking too long");
        }
        AuditLog.Entry entry = audit.event("connection_change", requestId).user(sub, null, null).system(systemId)
                .credentialType(CredentialType.USER_OAUTH.wire());
        boolean entryClosed = false;
        try {
            Connection current = connections.find(sub, systemId).orElseThrow(() -> new CredentialRequiredException(systemId));
            if (current.type() != CredentialType.USER_OAUTH || current.state() != Connection.StoredState.CONNECTED) {
                throw new CredentialRequiredException(systemId);
            }
            StoredCredential credential = seen != null && current.secretVersion() != null
                    && current.secretVersion().equals(seen.secretVersion()) ? seenCredential
                    : secrets.get(current.secretKey()).orElseThrow(() -> new CredentialRequiredException(systemId));
            if (!due(current, clock.instant().plus(window))) {
                return new Fresh(current, credential);
            }
            SecretValue refreshToken = credential.refreshToken();
            TokenSet tokens;
            try {
                if (refreshToken == null) {
                    throw new OAuthGrantRejectedException();
                }
                tokens = provider.refresh(refreshToken);
            } catch (OAuthGrantRejectedException e) {
                if (store.markRevoked(current)) {
                    entry.denied("oauth_grant_revoked", null);
                }
                throw new CredentialRequiredException(systemId);
            } catch (UpstreamUnavailableException e) {
                if (current.accessExpiresAt() != null && current.accessExpiresAt().isAfter(clock.instant())) {
                    log.warn("Token renewal for {} failed, current token still valid: {}", systemId, e.getMessage());
                    return new Fresh(current, credential);
                }
                entry.error("provider_unavailable", "upstream_unavailable");
                throw e;
            }
            Instant now = clock.instant();
            boolean rotated = tokens.refreshToken() != null && !tokens.refreshToken().reveal().equals(refreshToken.reveal());
            StoredCredential next = new StoredCredential(CredentialType.USER_OAUTH, tokens.accessToken(),
                    tokens.refreshToken() != null ? tokens.refreshToken() : refreshToken);
            Optional<Connection> saved;
            try {
                saved = store.refresh(current, next, accessExpiry(tokens, now));
            } catch (RuntimeException e) {
                entryClosed = true;
                if (rotated) {
                    abandonLostGrant(provider, current, tokens);
                    entry.error("refresh_token_lost", "upstream_unavailable");
                } else {
                    entry.error(failureReason(e), "upstream_unavailable");
                }
                throw e;
            }
            if (saved.isEmpty()) {
                // Disconnected or replaced while the provider was answering: the new tokens belong to nobody.
                revokeQuietly(provider, tokens.accessToken());
                revokeQuietly(provider, tokens.refreshToken());
                entry.denied("connection_changed_during_refresh", null);
                throw new CredentialRequiredException(systemId);
            }
            entry.ok("token_refreshed");
            return new Fresh(saved.get(), next);
        } catch (SecretStoreUnavailableException e) {
            if (!entryClosed) {
                entry.error("secret_store_unavailable", "upstream_unavailable");
            }
            throw e;
        } finally {
            lock.release(sub, systemId, owner.get());
        }
    }

    /**
     * The provider rotated the refresh token and the broker could not save the new one: the old one is spent, so
     * the grant is unusable for the broker. Revoking the new tokens keeps no live grant without an owner, and the
     * connection goes to "error" (not "revoked": the provider did not withdraw anything) until the user reconnects.
     */
    private void abandonLostGrant(OAuthProvider provider, Connection current, TokenSet tokens) {
        revokeQuietly(provider, tokens.accessToken());
        revokeQuietly(provider, tokens.refreshToken());
        try {
            store.markError(current);
        } catch (RuntimeException e) {
            log.error("Connection to {} could not be marked as failed after a lost refresh token ({})", current.system(),
                    e.getClass().getSimpleName());
        }
    }

    private static String failureReason(RuntimeException e) {
        return e instanceof SecretStoreUnavailableException ? "secret_store_unavailable"
                : CredentialService.unavailableDatabase(e) ? "database_unavailable" : "internal_error";
    }

    private static boolean due(Connection connection, Instant dueBefore) {
        return connection.accessExpiresAt() != null && !connection.accessExpiresAt().isAfter(dueBefore);
    }

    private ConfiguredSystem oauthSystem(String systemId) {
        return systems.find(systemId)
                .filter(s -> s.oauth().isPresent())
                .orElseThrow(() -> new InvalidRequestException("system does not accept OAuth connections"));
    }

    private AuditLog.Entry portalEntry(Caller.PortalUser caller, String systemId) {
        return audit.event("connection_change", caller.requestId())
                .user(caller.sub(), caller.username(), caller.azp())
                .system(systemId)
                .credentialType(CredentialType.USER_OAUTH.wire());
    }

    private static Instant accessExpiry(TokenSet tokens, Instant now) {
        return tokens.expiresInSeconds() == null ? null : now.plusSeconds(tokens.expiresInSeconds()).truncatedTo(ChronoUnit.SECONDS);
    }

    private void revokeQuietly(OAuthProvider provider, SecretValue token) {
        if (token == null) {
            return;
        }
        try {
            provider.revoke(token);
        } catch (UpstreamUnavailableException | SecretStoreUnavailableException e) {
            log.warn("Token not revoked at the provider: {}", e.getMessage());
        }
    }

    private static boolean constantTimeEquals(String expected, String given) {
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), given.getBytes(StandardCharsets.UTF_8));
    }

    private static String randomToken(int bytes) {
        byte[] value = new byte[bytes];
        RANDOM.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static String challenge(SecretValue verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.reveal().getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
