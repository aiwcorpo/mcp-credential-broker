package pl.aiwcorpo.mcp.broker.credential;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.RequestIds;
import pl.aiwcorpo.mcp.broker.authenticator.AuthenticatorService;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.oauth.OAuthFlowStore;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import pl.aiwcorpo.mcp.broker.system.UpstreamUnavailableException;

/**
 * Everything the broker removes on its own initiative or on the word of the offboarding channel: the purge of a user
 * (CC-155) and the cleanup of connections nobody uses. Both remove a connection the way a disconnect does (the
 * tokens of a user-oauth connection are revoked at the provider first, best effort; the secret goes before the row,
 * all KV versions; credential.invalidated is published) and differ in the audit reason.
 */
public class OffboardingService {

    private static final int MAX_PASSES = 50;
    private static final Logger log = LoggerFactory.getLogger(OffboardingService.class);

    private final ConnectionRepository connections;
    private final SecretStore secrets;
    private final InvalidationPublisher invalidations;
    private final OAuthService oauth;
    private final OAuthFlowStore flows;
    private final AuthenticatorService authenticator;
    private final AuditLog audit;
    private final Clock clock;
    private final BrokerProperties.Retention retention;

    public OffboardingService(ConnectionRepository connections, SecretStore secrets, InvalidationPublisher invalidations,
            OAuthService oauth, OAuthFlowStore flows, AuthenticatorService authenticator, AuditLog audit, Clock clock,
            BrokerProperties.Retention retention) {
        this.connections = connections;
        this.secrets = secrets;
        this.invalidations = invalidations;
        this.oauth = oauth;
        this.flows = flows;
        this.authenticator = authenticator;
        this.audit = audit;
        this.clock = clock;
        this.retention = retention;
    }

    /**
     * Removes every connection with its secrets, the OAuth flows in progress, the authenticator registration with its
     * seeds and the row that blocks the user. Idempotent, and the same for a user the broker has never seen. The steps
     * are independent: one that fails does not stop the others, so a secret store outage cannot keep the
     * registration alive; the first failure is rethrown (503) once every step has run, and the call is repeated.
     * Every call leaves one admin_change event, whatever it found.
     */
    public void purge(String requestId, String sub) {
        if (sub.isBlank() || sub.length() > 255) {
            // C4 knows 204, 403 and 503 here. No user has such a sub (the contract caps it at 255), so there is nothing to
            // remove; the call still leaves its one event, without a sub the schema would not take.
            audit.event("admin_change", requestId).ok("user_purged");
            return;
        }
        AuditLog.Entry summary = audit.event("admin_change", requestId).user(sub, null, null);
        List<RuntimeException> failures = new ArrayList<>();
        // Flows first: a flow still open could create a connection after the others are gone.
        attempt(failures, () -> flows.discardAll(sub, SystemRegistry.KNOWN_SYSTEMS));
        attempt(failures, () -> removeConnections(requestId, sub));
        attempt(failures, () -> authenticator.purge(requestId, sub));
        if (failures.isEmpty()) {
            summary.ok("user_purged");
            return;
        }
        RuntimeException first = failures.get(0);
        failures.stream().skip(1).forEach(first::addSuppressed);
        summary.error("user_purged", "upstream_unavailable");
        throw first;
    }

    private void removeConnections(String requestId, String sub) {
        List<RuntimeException> failures = new ArrayList<>();
        attempt(failures, () -> {
            for (Connection connection : connections.findAll(sub)) {
                attempt(failures, () -> remove(requestId, connection, "user_purged", null));
            }
        });
        // Values no row points at: a delete that failed once, or a row that was lost.
        attempt(failures, () -> secrets.deleteAllOf(sub));
        if (!failures.isEmpty()) {
            RuntimeException first = failures.get(0);
            failures.stream().skip(1).forEach(first::addSuppressed);
            throw first;
        }
    }

    /**
     * Deletes the connections whose last use is older than the retention. The row is read again under the lock of the
     * connection, so one that was used or removed since the query is left alone.
     *
     * @return how many connections were removed
     */
    public int removeUnused() {
        Instant cutoff = clock.instant().minus(retention.unusedAfter());
        int removed = 0;
        int skipped = 0;
        // Rows that fail stay at the front of the oldest-first query, so each pass skips the ones that failed in this run
        // instead of meeting them again; the next run tries them anew.
        for (int pass = 0; pass < MAX_PASSES; pass++) {
            List<Connection> batch = connections.findLastActivityBefore(cutoff, retention.batchSize(), skipped);
            if (batch.isEmpty()) {
                break;
            }
            for (Connection candidate : batch) {
                try {
                    if (remove(RequestIds.next(clock), candidate, "unused_cleanup", cutoff)) {
                        removed++;
                    }
                } catch (SecretStoreUnavailableException e) {
                    log.warn("Cleanup of unused connections stopped, the secret store or lock is unavailable: {}", e.getMessage());
                    return removed;
                } catch (RuntimeException e) {
                    if (CredentialService.unavailableDatabase(e)) {
                        log.warn("Cleanup of unused connections stopped, the database is unavailable");
                        return removed;
                    }
                    skipped++;
                    log.warn("Connection to {} not removed ({}: {})", candidate.system(), e.getClass().getSimpleName(),
                            e instanceof UpstreamUnavailableException ? e.getMessage() : "see audit");
                }
            }
        }
        return removed;
    }

    /** @param unusedSince when not null, the connection is removed only if its last use is before this instant */
    private boolean remove(String requestId, Connection candidate, String reason, Instant unusedSince) {
        AuditLog.Entry entry = audit.event("connection_change", requestId)
                .user(candidate.sub(), null, null)
                .system(candidate.system())
                .credentialType(candidate.type().wire())
                .backendUser(candidate.backendUser());
        try {
            Optional<Connection> removed = Optional.ofNullable(oauth.underRefreshLock(candidate.sub(), candidate.system(), () -> {
                Optional<Connection> current = connections.find(candidate.sub(), candidate.system());
                if (current.isEmpty() || (unusedSince != null && !lastActivity(current.get()).isBefore(unusedSince))) {
                    return null;
                }
                Connection existing = current.get();
                if (!oauth.revokeAtProvider(existing)) {
                    audit.event("connection_change", requestId)
                            .user(existing.sub(), null, null)
                            .system(existing.system())
                            .credentialType(existing.type().wire())
                            .error("provider_revoke_failed", null);
                }
                secrets.delete(existing.secretKey());
                connections.delete(existing.sub(), existing.system());
                invalidations.invalidated(existing.sub(), existing.system());
                return existing;
            }));
            removed.ifPresent(connection -> entry.ok(reason));
            return removed.isPresent();
        } catch (RuntimeException e) {
            entry.error(reason, "upstream_unavailable");
            throw e;
        }
    }

    private static Instant lastActivity(Connection connection) {
        return connection.lastUsedAt() != null ? connection.lastUsedAt() : connection.connectedAt();
    }

    private static void attempt(List<RuntimeException> failures, Runnable step) {
        try {
            step.run();
        } catch (RuntimeException e) {
            failures.add(e);
        }
    }
}
