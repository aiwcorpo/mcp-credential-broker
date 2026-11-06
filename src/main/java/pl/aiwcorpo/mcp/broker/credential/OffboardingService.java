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
import pl.aiwcorpo.mcp.broker.system.UpstreamUnavailableException;

/**
 * Everything the broker removes on its own initiative or on the word of the offboarding channel: the purge of a user
 * (CC-155) and the cleanup of connections nobody uses. Both remove a connection the way a disconnect does (the
 * tokens of a user-oauth connection are revoked at the provider first, best effort; the secret goes before the row,
 * all KV versions; credential.invalidated is published) and differ in the audit reason.
 */
public class OffboardingService {

    private static final int MAX_PASSES = 50;
    /** Unreadable stored values in one purge after which it stops: one is damage, several look like a wrong key or a broken store. */
    private static final int MAX_UNREADABLE_PER_PURGE = 3;
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
        // The marker first: a PUT or an OAuth completion that waits for the lock of a connection finds it and refuses,
        // so it cannot write the user back between the steps below.
        attempt(failures, () -> oauth.markPurging(sub, retention.purgeMarkerTtl()));
        // Without Redis neither the flows nor the locks can be reached, and each try costs its timeout: skip them. The
        // registration, which needs only the database and the secret store, is still removed.
        if (failures.isEmpty()) {
            // Flows first: a flow still open could create a connection after the others are gone.
            attempt(failures, () -> flows.discardAll(sub, oauth.systemIdsOf(sub)));
            attempt(failures, () -> removeConnections(requestId, sub));
        }
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
        java.util.concurrent.atomic.AtomicInteger unreadable = new java.util.concurrent.atomic.AtomicInteger();
        attempt(failures, () -> {
            for (Connection connection : connections.findAll(sub)) {
                attempt(failures, () -> {
                    if (unreadable.get() >= MAX_UNREADABLE_PER_PURGE) {
                        throw new SecretStoreUnavailableException("several stored values are unreadable in one purge");
                    }
                    remove(requestId, connection, "user_purged", null, unreadable::incrementAndGet);
                });
            }
        });
        // Values no row points at: a delete that failed once, or a row that was lost. Only when every connection went:
        // a connection that stayed still has tokens to revoke at the provider on the repeat, and this would delete them.
        if (failures.isEmpty()) {
            attempt(failures, () -> secrets.deleteAllOf(sub));
        }
        // A write that was already past the marker check when the purge started has finished once the locks are taken in
        // turn, so the second read of the rows sees it.
        if (failures.isEmpty()) {
            attempt(failures, () -> oauth.awaitWriters(sub));
        }
        if (failures.isEmpty()) {
            attempt(failures, () -> {
                for (Connection late : connections.findAll(sub)) {
                    attempt(failures, () -> remove(requestId, late, "user_purged", null, unreadable::incrementAndGet));
                }
            });
            if (failures.isEmpty()) {
                attempt(failures, () -> secrets.deleteAllOf(sub));
            }
        }
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

    /** What one sweep of orphaned secrets found; {@code refusedBecause} is set when it deleted nothing on purpose. */
    public record OrphanSweep(int scanned, int orphans, int deleted, String refusedBecause) {
    }

    /**
     * Finds stored values no row points at and older than {@code orphan-secrets-after}: a new version whose row switch
     * failed, or a delete that failed after the switch. Deleting is off unless {@code orphan-sweep-delete} is set, so by
     * default this only reports. Even then it refuses when the set of references is empty although the store is not, or
     * when more than {@code orphan-max-fraction} of the values would go (a broken or partial read of the rows would look
     * like that), deletes at most {@code orphan-max-deletes-per-run}, and leaves values of OAuth systems alone: without
     * the {@code sub} their grant cannot be revoked at the provider, and deleting the tokens would keep it alive there.
     * The store is listed first and the rows read after, so a row switched in between is seen.
     */
    public OrphanSweep sweepOrphanSecrets() {
        Instant cutoff = clock.instant().minus(retention.orphanSecretsAfter());
        List<SecretStore.Stored> listed = secrets.listStored();
        if (listed.isEmpty()) {
            return new OrphanSweep(0, 0, 0, null);
        }
        java.util.Set<String> referenced = connections.referencedSecretPaths();
        if (referenced.isEmpty()) {
            log.warn("Orphan sweep refused: the store holds {} values and no connection row points at any", listed.size());
            return new OrphanSweep(listed.size(), 0, 0, "no_references");
        }
        List<SecretStore.Stored> orphans = listed.stream()
                .filter(stored -> !stored.updatedAt().isAfter(cutoff))
                .filter(stored -> !referenced.contains(stored.subHash() + "/" + stored.system()
                        + (stored.version() == null ? "" : "/" + stored.version())))
                .toList();
        if (listed.size() >= 10 && orphans.size() > retention.orphanMaxFraction() * listed.size()) {
            log.warn("Orphan sweep refused: {} of {} stored values look orphaned, more than {}", orphans.size(), listed.size(),
                    retention.orphanMaxFraction());
            return new OrphanSweep(listed.size(), orphans.size(), 0, "too_many");
        }
        if (!retention.orphanSweepDelete()) {
            if (!orphans.isEmpty()) {
                log.info("Orphan sweep (report only): {} of {} stored values are not referenced by any row", orphans.size(), listed.size());
            }
            return new OrphanSweep(listed.size(), orphans.size(), 0, orphans.isEmpty() ? null : "report_only");
        }
        int deleted = 0;
        for (SecretStore.Stored orphan : orphans) {
            if (deleted >= retention.orphanMaxDeletesPerRun()) {
                break;
            }
            if (!oauth.isPlainSecretSystem(orphan.system())) {
                continue;
            }
            secrets.deleteStored(orphan);
            deleted++;
        }
        return new OrphanSweep(listed.size(), orphans.size(), deleted, null);
    }

    /** @param unusedSince when not null, the connection is removed only if its last use is before this instant */
    private boolean remove(String requestId, Connection candidate, String reason, Instant unusedSince) {
        return remove(requestId, candidate, reason, unusedSince, () -> { });
    }

    private boolean remove(String requestId, Connection candidate, String reason, Instant unusedSince, Runnable onUnreadable) {
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
                if (!oauth.revokeAtProvider(existing, onUnreadable)) {
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
