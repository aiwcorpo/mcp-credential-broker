package pl.aiwcorpo.mcp.broker.system;

import java.net.URI;
import java.time.Clock;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.broker.api.SystemAdminRequest;
import pl.aiwcorpo.mcp.broker.api.SystemAdminView;
import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.credential.Connection;
import pl.aiwcorpo.mcp.broker.credential.ConnectionRepository;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.credential.OAuthService;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;

/**
 * The admin API of the systems (C4 {@code /v1/admin/systems}): validation, storage in PostgreSQL, the OAuth client secret in
 * OpenBao, one {@code admin_change} event per change. The caller has already passed the certificate and token checks of the
 * filter; here it must also be in the group {@code mcp-platform-admin}.
 */
public class SystemAdminService {

    public static final String ADMIN_GROUP = "mcp-platform-admin";

    private static final Logger log = LoggerFactory.getLogger(SystemAdminService.class);
    private static final Pattern ETAG_HEADER = Pattern.compile("^\"([A-Za-z0-9_-]{8,128})\"$");
    private static final int PURGE_BATCH = 100;

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

    public SystemAdminService(SystemRepository repository, SystemRegistry registry, OAuthClientSecrets clientSecrets,
            ConnectionRepository connections, SecretStore secrets, InvalidationPublisher invalidations, OAuthService oauth,
            AuditLog audit, Clock clock, boolean allowPlainHttp) {
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
    }

    public List<SystemAdminView> list(Caller.PortalUser caller) {
        requireAdmin(caller, null);
        return repository.findAll().stream().map(SystemAdminService::view).toList();
    }

    public Stored get(Caller.PortalUser caller, String id) {
        requireAdmin(caller, id);
        SystemDefinition found = repository.find(id).orElseThrow(SystemAdminException::notFound);
        return new Stored(view(found), found.etag());
    }

    /**
     * Creates ({@code ifNoneMatch} is {@code *}) or replaces ({@code ifMatch} carries the etag read before) a system. A
     * replace keeps the client secret only while baseUrl, authorizeUrl, tokenUrl and clientId stay as they are, so that a
     * changed address never receives the old secret.
     */
    public Stored put(Caller.PortalUser caller, String id, SystemAdminRequest request, String ifMatch, String ifNoneMatch) {
        requireAdmin(caller, id);
        AuditLog.Entry entry = entry(caller, id);
        try {
            return write(id, request, ifMatch, ifNoneMatch, entry);
        } catch (SystemAdminException e) {
            entry.denied(e.reason() != null ? e.reason() : e.error(), "invalid_argument");
            throw e;
        } catch (RuntimeException e) {
            entry.error("system_change_failed", "upstream_unavailable");
            throw e;
        }
    }

    private Stored write(String id, SystemAdminRequest request, String ifMatch, String ifNoneMatch, AuditLog.Entry entry) {
        if (!SystemIds.hasValidShape(id)) {
            throw SystemAdminException.invalid("system id");
        }
        if (SystemIds.isReserved(id)) {
            throw SystemAdminException.rejected(new SystemRejectedException("system_reserved", "the system id is reserved"));
        }
        boolean create = "*".equals(ifNoneMatch == null ? null : ifNoneMatch.trim());
        if (ifNoneMatch != null && !create || create && ifMatch != null) {
            throw SystemAdminException.invalid("If-Match and If-None-Match");
        }
        if (!create && ifMatch == null) {
            throw SystemAdminException.preconditionRequired();
        }
        Optional<SystemDefinition> existing = repository.find(id);
        if (create ? existing.isPresent() : existing.isEmpty() || !etagOf(ifMatch).equals(existing.get().etag())) {
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
        boolean sameClient = previous != null && sameClientAndAddresses(previous, candidate);
        boolean secretKept = candidate.oauth() != null && secret == null && sameClient && previous.clientSecretSet();
        if (candidate.oauth() != null && secret == null && !sameClient) {
            throw SystemAdminException.rejected(new SystemRejectedException("client_secret_required",
                    "clientSecret is required when baseUrl, authorizeUrl, tokenUrl or clientId changes"));
        }
        SystemDefinition next = candidate.withClientSecretSet(secret != null || secretKept).withEtag(SystemDefinition.newEtag());
        boolean stored = create ? repository.insert(next, clock.instant()) : repository.update(next, previous.etag(), clock.instant());
        if (!stored) {
            throw SystemAdminException.preconditionFailed();
        }
        try {
            if (secret != null) {
                clientSecrets.write(id, SecretValue.of(secret));
            } else if (next.oauth() == null && previous != null && previous.oauth() != null) {
                clientSecrets.delete(id);
            }
        } catch (RuntimeException e) {
            undo(create, previous, next);
            throw e;
        }
        refresh();
        entry.ok(create ? "system_created" : "system_updated");
        return new Stored(view(next), next.etag());
    }

    /**
     * Removes the system, the connections of users to it with their secrets (each removal publishes credential.invalidated),
     * and the client secret. Idempotent, so a call that failed half way is repeated. The connections go first, while the
     * adapter can still revoke OAuth grants, and again after the row, for what a stale instance wrote in between.
     */
    public void delete(Caller.PortalUser caller, String id) {
        requireAdmin(caller, id);
        AuditLog.Entry entry = entry(caller, id);
        try {
            if (!SystemIds.hasValidShape(id)) {
                entry.ok("nothing_to_delete");
                return;
            }
            Optional<SystemDefinition> existing = repository.find(id);
            removeConnections(caller.requestId(), id);
            boolean deleted = repository.delete(id);
            refresh();
            removeConnections(caller.requestId(), id);
            if (existing.isEmpty() || existing.get().oauth() != null) {
                clientSecrets.delete(id);
            }
            entry.ok(deleted ? "system_deleted" : "nothing_to_delete");
        } catch (RuntimeException e) {
            entry.error("system_change_failed", "upstream_unavailable");
            throw e;
        }
    }

    private void removeConnections(String requestId, String id) {
        while (true) {
            List<Connection> batch = connections.findBySystem(id, PURGE_BATCH);
            if (batch.isEmpty()) {
                return;
            }
            int removed = 0;
            for (Connection candidate : batch) {
                Optional<Connection> gone = Optional.ofNullable(oauth.underRefreshLock(candidate.sub(), id, () -> {
                    Optional<Connection> current = connections.find(candidate.sub(), id);
                    if (current.isEmpty()) {
                        return null;
                    }
                    Connection existing = current.get();
                    if (!oauth.revokeAtProvider(existing)) {
                        audit.event("connection_change", requestId).user(existing.sub(), null, null).system(id)
                                .credentialType(existing.type().wire()).error("provider_revoke_failed", null);
                    }
                    secrets.delete(existing.secretKey());
                    connections.delete(existing.sub(), id);
                    invalidations.invalidated(existing.sub(), id);
                    return existing;
                }));
                gone.ifPresent(connection -> audit.event("connection_change", requestId).user(connection.sub(), null, null)
                        .system(id).credentialType(connection.type().wire()).backendUser(connection.backendUser())
                        .ok("system_deleted"));
                removed++;
            }
            if (removed == 0) {
                return;
            }
        }
    }

    /** The secret could not be written: the previous definition goes back, so the old secret is not left with a new address. */
    private void undo(boolean create, SystemDefinition previous, SystemDefinition next) {
        try {
            if (create) {
                repository.delete(next.id());
            } else {
                repository.update(previous.withEtag(SystemDefinition.newEtag()), next.etag(), clock.instant());
            }
            refresh();
        } catch (RuntimeException e) {
            log.error("System {} could not be restored after its client secret failed to store ({})", next.id(),
                    e.getClass().getSimpleName());
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
        URI baseUrl = url(request.baseUrl(), "baseUrl");
        SystemDefinition.Oauth oauth = null;
        if (request.oauth() != null) {
            SystemAdminRequest.Oauth client = request.oauth();
            List<String> scopes = client.scopes() == null ? List.of() : client.scopes();
            if (new HashSet<>(scopes).size() != scopes.size()) {
                throw SystemAdminException.invalid("scopes");
            }
            URI revoke = previous != null && previous.oauth() != null ? previous.oauth().revokeUrl() : null;
            oauth = new SystemDefinition.Oauth(client.clientId(), url(client.authorizeUrl(), "authorizeUrl"),
                    url(client.tokenUrl(), "tokenUrl"), revoke, scopes);
        }
        boolean sameScheme = previous != null && previous.secretScheme() == request.secretScheme();
        return new SystemDefinition(id, baseUrl, request.adapter(), List.copyOf(request.supportedTypes()), request.defaultType(),
                request.secretScheme(), oauth, false, previous == null ? null : previous.timeout(),
                previous == null ? null : previous.exchangeAudience(), sameScheme ? previous.userSecretScheme() : null,
                previous == null ? null : previous.deployment(), null);
    }

    private URI url(String value, String field) {
        try {
            URI uri = URI.create(value);
            boolean https = "https".equals(uri.getScheme());
            if ((!https && !("http".equals(uri.getScheme()) && allowPlainHttp)) || uri.getHost() == null || uri.getUserInfo() != null) {
                throw SystemAdminException.invalid(field);
            }
            return uri;
        } catch (IllegalArgumentException e) {
            throw SystemAdminException.invalid(field);
        }
    }

    private static boolean sameClientAndAddresses(SystemDefinition before, SystemDefinition after) {
        return before.oauth() != null && after.oauth() != null && before.baseUrl().equals(after.baseUrl())
                && before.oauth().clientId().equals(after.oauth().clientId())
                && java.util.Objects.equals(before.oauth().authorizeUrl(), after.oauth().authorizeUrl())
                && java.util.Objects.equals(before.oauth().tokenUrl(), after.oauth().tokenUrl());
    }

    private static String etagOf(String header) {
        Matcher matcher = ETAG_HEADER.matcher(header.trim());
        if (!matcher.matches()) {
            throw SystemAdminException.invalid("If-Match");
        }
        return matcher.group(1);
    }

    private void requireAdmin(Caller.PortalUser caller, String id) {
        if (!caller.hasGroup(ADMIN_GROUP)) {
            entry(caller, id).denied("not_admin", "access_denied");
            throw SystemAdminException.forbidden();
        }
    }

    private AuditLog.Entry entry(Caller.PortalUser caller, String id) {
        return audit.event("admin_change", caller.requestId()).user(caller.sub(), caller.username(), caller.azp()).system(id);
    }

    static SystemAdminView view(SystemDefinition system) {
        SystemDefinition.Oauth client = system.oauth();
        return new SystemAdminView(system.id(), system.baseUrl().toString(), system.adapter(),
                system.supportedTypes().stream().map(CredentialType::wire).toList(), system.defaultType().wire(),
                system.secretScheme().wire(), client == null ? null : new SystemAdminView.Oauth(client.clientId(),
                        client.authorizeUrl() == null ? client.tokenUrl().toString() : client.authorizeUrl().toString(),
                        client.tokenUrl().toString(), client.scopes(), system.clientSecretSet()));
    }
}
