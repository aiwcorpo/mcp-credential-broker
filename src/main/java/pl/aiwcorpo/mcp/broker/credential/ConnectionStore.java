package pl.aiwcorpo.mcp.broker.credential;

import java.time.Clock;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.StoredCredential;

/**
 * Writes a connection's value and metadata together. Each stored value gets its own path; the connection row
 * points at it. A replacement is written next to the old value and only the row switches, so a failure in
 * between leaves the previous credential intact, and the old path (all KV versions) is deleted only after
 * the switch.
 */
public class ConnectionStore {

    private static final Logger log = LoggerFactory.getLogger(ConnectionStore.class);

    private final ConnectionRepository connections;
    private final SecretStore secrets;
    private final InvalidationPublisher invalidations;
    private final Clock clock;

    public ConnectionStore(ConnectionRepository connections, SecretStore secrets, InvalidationPublisher invalidations, Clock clock) {
        this.connections = connections;
        this.secrets = secrets;
        this.invalidations = invalidations;
        this.clock = clock;
    }

    /**
     * @param announce publish credential.invalidated when a previous connection existed (CC-046); false for a
     *                 token refresh, which keeps the same grant
     */
    Connection replace(Connection template, StoredCredential credential, Optional<Connection> previous, boolean announce) {
        SecretKey key = SecretKey.newVersion(template.sub(), template.system());
        secrets.put(key, credential);
        Connection next = template.withSecretVersion(key.version());
        try {
            connections.upsert(next, clock.instant());
        } catch (RuntimeException e) {
            deleteQuietly(key);
            throw e;
        }
        previous.ifPresent(old -> deleteQuietly(old.secretKey()));
        if (announce && previous.isPresent()) {
            invalidations.invalidated(template.sub(), template.system());
        }
        return next;
    }

    /** The provider no longer honours the grant: the value is useless, the row stays so the portal shows "revoked". */
    void markRevoked(Connection connection) {
        connections.setState(connection.sub(), connection.system(), Connection.StoredState.REVOKED, clock.instant());
        invalidations.invalidated(connection.sub(), connection.system());
        deleteQuietly(connection.secretKey());
    }

    void deleteQuietly(SecretKey key) {
        try {
            secrets.delete(key);
        } catch (RuntimeException e) {
            log.error("Unreferenced secret for system {} could not be removed ({})", key.system(),
                    e.getClass().getSimpleName());
        }
    }
}
