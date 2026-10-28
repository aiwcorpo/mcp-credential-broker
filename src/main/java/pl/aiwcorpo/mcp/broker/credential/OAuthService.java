package pl.aiwcorpo.mcp.broker.credential;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

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
 * to the {@code sub} that started it; whoever completes it must present the same {@code sub}, the flow's
 * {@code state}, and a code that the provider issued for the same account as the SSO identity (C4.1).
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
        try {
            ConfiguredSystem system = oauthSystem(systemId);
            OAuthProvider provider = system.oauth().orElseThrow();
            OAuthFlowStore.Flow pending = flows.peek(flowId).orElseThrow(() -> new SecretRejectedException("flow_invalid"));
            if (!pending.sub().equals(caller.sub())) {
                // Not consumed: someone else's request must not be able to burn the owner's flow.
                throw new SecretRejectedException("flow_invalid", "flow_of_another_user");
            }
            OAuthFlowStore.Flow flow = flows.take(flowId).orElseThrow(() -> new SecretRejectedException("flow_invalid"));
            if (!flow.system().equals(system.id()) || !constantTimeEquals(flow.state(), state)) {
                throw new SecretRejectedException("flow_invalid", "state_mismatch");
            }
            TokenSet tokens;
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
            if (!IdentityRule.matches(system.config().identityClaim(), caller.claims(), identity)) {
                revokeQuietly(provider, tokens.accessToken());
                revokeQuietly(provider, tokens.refreshToken());
                throw new SecretRejectedException("identity_mismatch");
            }
            Instant now = clock.instant();
            Optional<Connection> previous = connections.find(caller.sub(), system.id());
            store.replace(
                    new Connection(caller.sub(), system.id(), CredentialType.USER_OAUTH, Connection.StoredState.CONNECTED,
                            identity.username(), null, now.truncatedTo(ChronoUnit.SECONDS), null, null,
                            accessExpiry(tokens, now)),
                    new StoredCredential(CredentialType.USER_OAUTH, tokens.accessToken(), tokens.refreshToken()),
                    previous, true);
            entry.ok(previous.isPresent() ? "oauth_replaced" : "oauth_connected");
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
        }
    }

    /**
     * Renews the access token when it has less than the refresh margin left, so a token handed to the gateway
     * stays valid for longer than the gateway caches it. Provider failure while the current token still works
     * is not an error for the caller.
     */
    public Fresh ensureFresh(String requestId, Connection found, StoredCredential stored) {
        Instant now = clock.instant();
        if (!due(found, now)) {
            return new Fresh(found, stored);
        }
        return renew(requestId, found.sub(), found.system(), found, stored, false);
    }

    /** Background renewal of tokens that will be due within the sweep window. */
    public int refreshDue() {
        List<Connection> due = connections.findOAuthExpiringBefore(clock.instant().plus(settings.sweepWindow()), SWEEP_BATCH);
        int renewed = 0;
        for (Connection connection : due) {
            try {
                renew(RequestIds.next(clock), connection.sub(), connection.system(), null, null, true);
                renewed++;
            } catch (CredentialRequiredException e) {
                log.info("Connection to {} no longer renewable", connection.system());
            } catch (RuntimeException e) {
                log.warn("Token renewal for {} failed ({})", connection.system(), e.getClass().getSimpleName());
            }
        }
        return renewed;
    }

    /** Best effort: the connection is removed locally whether or not the provider could be reached. */
    public void revokeAtProvider(Connection connection) {
        Optional<ConfiguredSystem> system = systems.find(connection.system());
        if (connection.type() != CredentialType.USER_OAUTH || connection.state() != Connection.StoredState.CONNECTED
                || system.isEmpty() || system.get().oauth().isEmpty()) {
            return;
        }
        try {
            StoredCredential stored = secrets.get(connection.secretKey()).orElse(null);
            if (stored != null) {
                OAuthProvider provider = system.get().oauth().get();
                revokeQuietly(provider, stored.refreshToken());
                revokeQuietly(provider, stored.value());
            }
        } catch (SecretStoreUnavailableException e) {
            log.warn("Token for {} not revoked at the provider: {}", connection.system(), e.getMessage());
        }
    }

    /** @param force renew even if the margin is not reached yet: the sweep runs ahead of the margin on purpose */
    private Fresh renew(String requestId, String sub, String systemId, Connection seen, StoredCredential seenCredential,
            boolean force) {
        ConfiguredSystem system = systems.find(systemId).orElseThrow(() -> new CredentialRequiredException(systemId));
        OAuthProvider provider = system.oauth().orElseThrow(() -> new CredentialRequiredException(systemId));
        Instant start = clock.instant();
        if (!lock.acquire(sub, systemId, settings.refreshLockWait())) {
            if (seen != null && seen.accessExpiresAt() != null && seen.accessExpiresAt().isAfter(start)) {
                return new Fresh(seen, seenCredential);
            }
            throw new UpstreamUnavailableException("token renewal is taking too long");
        }
        AuditLog.Entry entry = audit.event("connection_change", requestId).user(sub, null, null).system(systemId)
                .credentialType(CredentialType.USER_OAUTH.wire());
        try {
            Connection current = connections.find(sub, systemId).orElseThrow(() -> new CredentialRequiredException(systemId));
            if (current.type() != CredentialType.USER_OAUTH || current.state() != Connection.StoredState.CONNECTED) {
                throw new CredentialRequiredException(systemId);
            }
            StoredCredential credential = seen != null && current.secretVersion() != null
                    && current.secretVersion().equals(seen.secretVersion()) ? seenCredential
                    : secrets.get(current.secretKey()).orElseThrow(() -> new CredentialRequiredException(systemId));
            if (!force && !due(current, clock.instant())) {
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
                store.markRevoked(current);
                entry.denied("oauth_grant_revoked", null);
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
            StoredCredential next = new StoredCredential(CredentialType.USER_OAUTH, tokens.accessToken(),
                    tokens.refreshToken() != null ? tokens.refreshToken() : refreshToken);
            Connection saved = store.replace(current.withAccessExpiresAt(accessExpiry(tokens, now)), next,
                    Optional.of(current), false);
            entry.ok("token_refreshed");
            return new Fresh(saved, next);
        } catch (SecretStoreUnavailableException e) {
            entry.error("secret_store_unavailable", "upstream_unavailable");
            throw e;
        } finally {
            lock.release(sub, systemId);
        }
    }

    private boolean due(Connection connection, Instant now) {
        return connection.accessExpiresAt() != null && !connection.accessExpiresAt().isAfter(now.plus(settings.refreshMargin()));
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
        } catch (UpstreamUnavailableException e) {
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
