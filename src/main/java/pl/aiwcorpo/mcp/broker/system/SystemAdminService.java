package pl.aiwcorpo.mcp.broker.system;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.support.TransactionTemplate;

import pl.aiwcorpo.mcp.broker.api.SystemAdminRequest;
import pl.aiwcorpo.mcp.broker.api.SystemAdminView;
import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.Connection;
import pl.aiwcorpo.mcp.broker.credential.ConnectionRepository;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.credential.OAuthService;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.secret.ClientSecretConflictException;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;

/**
 * The admin API of the systems (C4 {@code /v1/admin/systems}): validation, storage in PostgreSQL, the OAuth client secret in
 * OpenBao, one {@code admin_change} event per change. The caller has already passed the certificate and token checks of the
 * filter; here it must also be in the group {@code mcp-platform-admin}, and for a write its token must carry an MFA
 * authentication of the last five minutes.
 *
 * <p>Order of a write: the secret goes to OpenBao first as a new version (check-and-set), the row is then updated under the
 * etag that was read, with the version and a new etag in the same statement. A write that loses the race destroys the version
 * it wrote, so two concurrent changes never leave the secret of one beside the configuration of the other.
 *
 * <p>When a change moves where the system points, every connection of the system loses its grant and its stored value and is
 * marked {@code needs_reconnect}. Nothing is sent to a provider: the old and the new address may both be ones the
 * administrator no longer controls. A delete likewise never calls a provider.
 */
public class SystemAdminService {

    public static final String ADMIN_GROUP = "mcp-platform-admin";
    public static final Duration MFA_WINDOW = Duration.ofSeconds(300);

    private static final Logger log = LoggerFactory.getLogger(SystemAdminService.class);
    private static final Pattern ETAG_HEADER = Pattern.compile("^\"([A-Za-z0-9_-]{8,128})\"$");
    private static final int BATCH = 100;
    private static final int DELETE_ATTEMPTS = 3;

    public record Stored(SystemAdminView view, String etag) {
    }

    private final SystemRepository repository;
    private final SystemRegistry registry;
    private final OAuthClientSecrets clientSecrets;
    private final ConnectionRepository connections;
    private final SecretStore secrets;
    private final InvalidationPublisher invalidations;
    private final OAuthService oauth;
    private final AuditLog audit;
    private final Clock clock;
    private final boolean allowPlainHttp;
    private final URI idpTokenUrl;
    private final TransactionTemplate transaction;
    private final BrokerProperties.BffToken mfaRules;
    private final BrokerProperties.TokenExchangePolicy tokenExchangePolicy;

    public SystemAdminService(SystemRepository repository, SystemRegistry registry, OAuthClientSecrets clientSecrets,
            ConnectionRepository connections, SecretStore secrets, InvalidationPublisher invalidations, OAuthService oauth,
            AuditLog audit, Clock clock, boolean allowPlainHttp, URI idpTokenUrl, TransactionTemplate transaction,
            BrokerProperties.BffToken mfaRules, BrokerProperties.TokenExchangePolicy tokenExchangePolicy) {
        this.repository = repository;
        this.registry = registry;
        this.clientSecrets = clientSecrets;
        this.connections = connections;
        this.secrets = secrets;
        this.invalidations = invalidations;
        this.oauth = oauth;
        this.audit = audit;
        this.clock = clock;
        this.allowPlainHttp = allowPlainHttp;
        this.idpTokenUrl = idpTokenUrl;
        this.transaction = transaction;
        this.mfaRules = mfaRules;
        this.tokenExchangePolicy = tokenExchangePolicy;
    }

    public List<SystemAdminView> list(Caller.PortalUser caller) {
        requireAdmin(caller);
        return repository.findAll().stream().map(SystemAdminService::view).toList();
    }

    public Stored get(Caller.PortalUser caller, String id) {
        requireAdmin(caller);
        if (!SystemIds.isValid(id)) {
            throw SystemAdminException.invalid("system id");
        }
        SystemDefinition found = repository.find(id).orElseThrow(SystemAdminException::notFound);
        return new Stored(view(found), found.etag());
    }

    public Stored put(Caller.PortalUser caller, String id, SystemAdminRequest request, String ifMatch, String ifNoneMatch) {
        requireAdmin(caller);
        requireFreshMfa(caller);
        AuditLog.Entry entry = entry(caller);
        try {
            return write(caller, id, request, ifMatch, ifNoneMatch, entry);
        } catch (SystemAdminException e) {
            entry.denied(e.reason() != null ? e.reason() : e.error(), "invalid_argument");
            throw e;
        } catch (RuntimeException e) {
            entry.error("system_change_failed", "upstream_unavailable");
            throw e;
        }
    }

    private Stored write(Caller.PortalUser caller, String id, SystemAdminRequest request, String ifMatch, String ifNoneMatch,
            AuditLog.Entry entry) {
        if (!SystemIds.hasValidShape(id)) {
            throw SystemAdminException.invalid("system id");
        }
        if (SystemIds.isReserved(id)) {
            throw SystemAdminException.rejected(new SystemRejectedException("system_reserved", "the system id is reserved"));
        }
        entry.systemBeingChanged(id);
        boolean create = "*".equals(ifNoneMatch == null ? null : ifNoneMatch.trim());
        if (ifNoneMatch != null && !create || create && ifMatch != null) {
            throw SystemAdminException.invalid("If-Match and If-None-Match");
        }
        String expectedEtag = ifMatch == null ? null : etagOf(ifMatch);
        if (!create && ifMatch == null) {
            throw SystemAdminException.preconditionRequired();
        }
        Optional<SystemDefinition> existing = repository.find(id);
        if (create ? existing.isPresent() : existing.isEmpty() || !expectedEtag.equals(existing.get().etag())) {
            throw SystemAdminException.preconditionFailed();
        }
        SystemDefinition previous = create ? null : existing.get();
        String secret = request.oauth() == null ? null : request.oauth().clientSecret();
        SystemDefinition candidate = definition(id, request, previous);
        try {
            SystemRules.check(candidate);
        } catch (SystemRejectedException e) {
            throw SystemAdminException.rejected(e);
        }
        if (candidate.supportedTypes().contains(CredentialType.TOKEN_EXCHANGE) && !tokenExchangePolicy.allows(candidate.exchangeAudience())) {
            throw SystemAdminException.rejected(new SystemRejectedException("audience_not_allowed",
                    "the audience is not in broker.token-exchange.allowed-audiences"));
        }
        boolean pointsMoved = previous == null || !candidate.pointsSameAs(previous);
        boolean keepsSecret = candidate.oauth() != null && secret == null && !pointsMoved && previous.secretVersion() != null;
        if (candidate.oauth() != null && secret == null && (previous == null || previous.oauth() == null || pointsMoved)) {
            throw SystemAdminException.rejected(new SystemRejectedException("client_secret_required",
                    "clientSecret is required when baseUrl, authorizeUrl, tokenUrl, clientId or revokeUrl changes"));
        }
        if (create && removeConnections(caller.requestId(), id) > 0) {
            audit.event("admin_change", caller.requestId()).user(caller.sub(), caller.username(), caller.azp())
                    .systemBeingChanged(id).ok("connections_invalidated");
        }

        Integer written = null;
        if (secret != null) {
            try {
                written = clientSecrets.write(id, SecretValue.of(secret));
            } catch (ClientSecretConflictException e) {
                throw SystemAdminException.preconditionFailed();
            }
        }
        Integer version = written != null ? written : keepsSecret ? previous.secretVersion() : null;
        SystemDefinition next = candidate.withSecretVersion(version).withEtag(SystemDefinition.newToken())
                .withClientRevision(pointsMoved ? SystemDefinition.newToken() : previous.clientRevision());
        boolean stored;
        try {
            // The connections stop being usable in the very transaction that moves the system; deleting their stored values
            // follows and is repeated by every later write until it is done.
            stored = Boolean.TRUE.equals(transaction.execute(status -> {
                Instant now = clock.instant();
                boolean done = create ? repository.insert(next, now) : repository.update(next, previous.etag(), now);
                if (done && !create && pointsMoved) {
                    connections.markAllNeedsReconnect(id, now);
                }
                return done;
            }));
        } catch (RuntimeException e) {
            destroyQuietly(id, written);
            throw e;
        }
        if (!stored) {
            destroyQuietly(id, written);
            throw SystemAdminException.preconditionFailed();
        }
        if (previous != null && previous.secretVersion() != null && !Objects.equals(previous.secretVersion(), version)) {
            destroyQuietly(id, previous.secretVersion());
        }
        refresh();
        entry.ok(create ? "system_created" : "system_updated");
        if (previous != null && completeInvalidation(caller.requestId(), id, next.clientRevision()) > 0) {
            audit.event("admin_change", caller.requestId()).user(caller.sub(), caller.username(), caller.azp())
                    .systemBeingChanged(id).ok("connections_invalidated");
        }
        return new Stored(view(next), next.etag());
    }

    /**
     * Removes the system, the connections of users to it with their stored values (each removal publishes
     * credential.invalidated), the row and the version of the client secret. Nothing is sent to a provider: a grant is not
     * revoked with a definition other than the one it was issued under, and the one it was issued under may be gone. An id
     * without a system is answered 204 and touches nothing. Repeating the call after a failure finishes the job: the row goes
     * last.
     */
    public void delete(Caller.PortalUser caller, String id, String ifMatch) {
        requireAdmin(caller);
        requireFreshMfa(caller);
        AuditLog.Entry entry = entry(caller);
        try {
            if (!SystemIds.isValid(id)) {
                throw SystemAdminException.invalid("system id");
            }
            String expectedEtag = ifMatch == null ? null : etagOf(ifMatch);
            Optional<SystemDefinition> existing = repository.find(id);
            if (existing.isEmpty()) {
                entry.ok("nothing_to_delete");
                return;
            }
            entry.systemBeingChanged(id);
            SystemDefinition system = existing.get();
            if (ifMatch == null) {
                throw SystemAdminException.preconditionRequired();
            }
            if (!expectedEtag.equals(system.etag())) {
                throw SystemAdminException.preconditionFailed();
            }
            int removed = removeConnections(caller.requestId(), id);
            boolean deleted = false;
            for (int attempt = 1; !deleted; attempt++) {
                try {
                    deleted = repository.delete(id, system.etag());
                    if (!deleted) {
                        throw SystemAdminException.preconditionFailed();
                    }
                } catch (DataIntegrityViolationException e) {
                    // A connection was written by an instance that had not yet seen the delete: take it too and try again.
                    if (attempt >= DELETE_ATTEMPTS) {
                        throw e;
                    }
                    removed += removeConnections(caller.requestId(), id);
                }
            }
            destroyQuietly(id, system.secretVersion());
            refresh();
            if (removed > 0) {
                audit.event("admin_change", caller.requestId()).user(caller.sub(), caller.username(), caller.azp())
                        .systemBeingChanged(id).ok("connections_invalidated");
            }
            entry.ok("system_deleted");
        } catch (SystemAdminException e) {
            entry.denied(e.reason() != null ? e.reason() : e.error(), "invalid_argument");
            throw e;
        } catch (RuntimeException e) {
            entry.error("system_change_failed", "upstream_unavailable");
            throw e;
        }
    }

    /**
     * Finishes what a change of where the system points started: connections not yet marked that were not issued under
     * {@code revision} (a write of an instance that had not seen the change) are marked, and the stored value of every marked
     * connection is deleted. Nothing is sent to anybody. A failure fails the write, and the next write of the system takes
     * up the rest.
     */
    private int completeInvalidation(String requestId, String id, String revision) {
        int done = 0;
        while (true) {
            List<Connection> batch = connections.findNeedingInvalidation(id, revision, BATCH);
            if (batch.isEmpty()) {
                return done;
            }
            for (Connection candidate : batch) {
                Connection gone = oauth.underRefreshLock(candidate.sub(), id, () -> {
                    Optional<Connection> current = connections.find(candidate.sub(), id);
                    if (current.isEmpty()) {
                        return null;
                    }
                    Connection row = current.get();
                    boolean unmarked = row.state() != Connection.StoredState.NEEDS_RECONNECT && !revision.equals(row.clientRevision());
                    boolean valueLeft = row.state() == Connection.StoredState.NEEDS_RECONNECT && row.secretVersion() != null;
                    if (!unmarked && !valueLeft) {
                        return null;
                    }
                    if (unmarked) {
                        connections.markNeedsReconnect(candidate.sub(), id, clock.instant());
                    }
                    secrets.delete(row.secretKey());
                    connections.clearSecretVersion(candidate.sub(), id);
                    invalidations.invalidated(candidate.sub(), id);
                    return row;
                });
                if (gone != null) {
                    done++;
                    audit.event("connection_change", requestId).user(gone.sub(), null, null).systemBeingChanged(id)
                            .credentialType(gone.type().wire()).backendUser(gone.backendUser()).ok("connections_invalidated");
                }
            }
        }
    }

    /** Deletes every connection of the system with its stored value, without calling anybody. */
    private int removeConnections(String requestId, String id) {
        int done = 0;
        while (true) {
            List<Connection> batch = connections.findBySystem(id, BATCH);
            if (batch.isEmpty()) {
                return done;
            }
            for (Connection candidate : batch) {
                Connection gone = oauth.underRefreshLock(candidate.sub(), id, () -> {
                    Optional<Connection> current = connections.find(candidate.sub(), id);
                    if (current.isEmpty()) {
                        return null;
                    }
                    secrets.delete(current.get().secretKey());
                    connections.delete(candidate.sub(), id);
                    invalidations.invalidated(candidate.sub(), id);
                    return current.get();
                });
                if (gone != null) {
                    done++;
                    audit.event("connection_change", requestId).user(gone.sub(), null, null).systemBeingChanged(id)
                            .credentialType(gone.type().wire()).backendUser(gone.backendUser()).ok("system_deleted");
                }
            }
        }
    }

    private void destroyQuietly(String id, Integer version) {
        if (version == null) {
            return;
        }
        try {
            clientSecrets.destroy(id, version);
        } catch (RuntimeException e) {
            log.warn("Version {} of the client secret of {} was not destroyed ({})", version, id, e.getClass().getSimpleName());
        }
    }

    private void refresh() {
        try {
            registry.reload();
        } catch (RuntimeException e) {
            log.warn("Systems not reloaded after a change, the next refresh picks it up ({})", e.getClass().getSimpleName());
        }
    }

    private SystemDefinition definition(String id, SystemAdminRequest request, SystemDefinition previous) {
        if (!SystemRules.ADAPTERS.contains(request.adapter())) {
            throw SystemAdminException.invalid("adapter");
        }
        if (new HashSet<>(request.supportedTypes()).size() != request.supportedTypes().size()) {
            throw SystemAdminException.invalid("supportedTypes");
        }
        List<CredentialType> types = List.copyOf(request.supportedTypes());
        boolean userOauth = types.contains(CredentialType.USER_OAUTH);
        boolean exchange = types.contains(CredentialType.TOKEN_EXCHANGE);
        URI baseUrl = url(request.baseUrl(), "baseUrl");
        URI revokeUrl = request.revokeUrl() == null ? null : url(request.revokeUrl(), "revokeUrl");
        if (revokeUrl != null && !userOauth) {
            throw SystemAdminException.rejected(new SystemRejectedException("revoke_url_not_settable",
                    "revokeUrl belongs to a system with user-oauth"));
        }
        SystemDefinition.Oauth oauth = null;
        if (request.oauth() != null) {
            SystemAdminRequest.Oauth client = request.oauth();
            List<String> scopes = client.scopes() == null ? List.of() : client.scopes();
            if (new HashSet<>(scopes).size() != scopes.size()) {
                throw SystemAdminException.invalid("scopes");
            }
            if (client.authorizeUrl() != null && !userOauth) {
                throw SystemAdminException.rejected(new SystemRejectedException("authorize_url_not_settable",
                        "authorizeUrl belongs to a system with user-oauth"));
            }
            if (exchange && client.tokenUrl() != null) {
                throw SystemAdminException.rejected(new SystemRejectedException("token_url_not_settable",
                        "a token-exchange system uses the token endpoint of the identity provider of the broker"));
            }
            oauth = new SystemDefinition.Oauth(client.clientId(),
                    client.authorizeUrl() == null ? null : url(client.authorizeUrl(), "authorizeUrl"),
                    exchange ? idpTokenUrl : client.tokenUrl() == null ? null : url(client.tokenUrl(), "tokenUrl"), revokeUrl, scopes);
        }
        CredentialScheme userScheme = request.userSecretScheme();
        if (userScheme != null && userScheme != CredentialScheme.BEARER && userScheme != CredentialScheme.BASIC) {
            throw SystemAdminException.invalid("userSecretScheme");
        }
        return new SystemDefinition(id, baseUrl, request.adapter(), request.product(), types, request.defaultType(),
                request.secretScheme(), oauth, null, request.timeout() == null ? null : Duration.parse(request.timeout()),
                request.exchangeAudience(), userScheme, previous == null ? null : previous.deployment(), null, null,
                request.displayName());
    }

    private URI url(String value, String field) {
        URI uri = SystemUrls.parse(value, allowPlainHttp);
        if (uri == null) {
            throw SystemAdminException.invalid(field);
        }
        return uri;
    }

    private static String etagOf(String header) {
        Matcher matcher = ETAG_HEADER.matcher(header.trim());
        if (!matcher.matches()) {
            throw SystemAdminException.invalid("If-Match");
        }
        return matcher.group(1);
    }

    private void requireAdmin(Caller.PortalUser caller) {
        if (!caller.hasGroup(ADMIN_GROUP)) {
            entry(caller).denied("not_admin", "access_denied");
            throw SystemAdminException.forbidden();
        }
    }

    /**
     * The BFF asks for a fresh MFA too; the broker does not rely on it. A recent login is not enough: the token must also say
     * that it was an MFA (an {@code acr} or {@code amr} the configuration names), because a password login is recent too.
     */
    private void requireFreshMfa(Caller.PortalUser caller) {
        Instant authenticated = caller.authTime();
        Instant now = clock.instant();
        boolean fresh = authenticated != null && !authenticated.isBefore(now.minus(MFA_WINDOW)) && !authenticated.isAfter(now.plus(MFA_WINDOW));
        if (!fresh || !mfaRules.provesMfa(caller.acr(), caller.amr())) {
            entry(caller).denied("step_up_required", "step_up_required");
            throw SystemAdminException.stepUpRequired();
        }
    }

    private AuditLog.Entry entry(Caller.PortalUser caller) {
        return audit.event("admin_change", caller.requestId()).user(caller.sub(), caller.username(), caller.azp());
    }

    static SystemAdminView view(SystemDefinition system) {
        SystemDefinition.Oauth client = system.oauth();
        return new SystemAdminView(system.id(), system.displayName() == null ? system.id() : system.displayName(),
                system.baseUrl().toString(), system.adapter(), system.product(),
                system.supportedTypes().stream().map(CredentialType::wire).toList(), system.defaultType().wire(),
                system.secretScheme().wire(), client == null || client.revokeUrl() == null ? null : client.revokeUrl().toString(),
                system.timeout() == null ? null : system.timeout().toString(), system.exchangeAudience(),
                system.userSecretScheme() == null ? null : system.userSecretScheme().wire(),
                client == null ? null : new SystemAdminView.Oauth(client.clientId(),
                        client.authorizeUrl() == null ? null : client.authorizeUrl().toString(),
                        client.tokenUrl() == null ? null : client.tokenUrl().toString(), client.scopes(), system.clientSecretSet()));
    }
}
