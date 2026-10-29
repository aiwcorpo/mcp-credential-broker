package pl.aiwcorpo.mcp.broker.credential;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;

public class ConnectionRepository {

    private final JdbcClient jdbc;

    public ConnectionRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<Connection> find(String sub, String system) {
        return jdbc.sql("""
                select sub, system, type, state, backend_user, expires_at, connected_at, last_used_at, secret_version, access_expires_at
                from connection where sub = :sub and system = :system
                """)
                .param("sub", sub)
                .param("system", system)
                .query(ConnectionRepository::map)
                .optional();
    }

    public void upsert(Connection connection, Instant now) {
        jdbc.sql("""
                insert into connection (sub, system, type, state, backend_user, expires_at, connected_at, last_used_at, secret_version, access_expires_at, updated_at)
                values (:sub, :system, :type, :state, :backendUser, :expiresAt, :connectedAt, :lastUsedAt, :secretVersion, :accessExpiresAt, :now)
                on conflict (sub, system) do update set
                    type = excluded.type, state = excluded.state, backend_user = excluded.backend_user,
                    expires_at = excluded.expires_at, connected_at = excluded.connected_at,
                    last_used_at = excluded.last_used_at, secret_version = excluded.secret_version,
                    access_expires_at = excluded.access_expires_at,
                    updated_at = excluded.updated_at
                """)
                .param("sub", connection.sub())
                .param("system", connection.system())
                .param("type", connection.type().wire())
                .param("state", connection.state().name().toLowerCase(Locale.ROOT))
                .param("backendUser", connection.backendUser())
                .param("expiresAt", timestamp(connection.expiresAt()))
                .param("connectedAt", timestamp(connection.connectedAt()))
                .param("lastUsedAt", timestamp(connection.lastUsedAt()))
                .param("secretVersion", connection.secretVersion())
                .param("accessExpiresAt", timestamp(connection.accessExpiresAt()))
                .param("now", timestamp(now))
                .update();
    }

    public List<Connection> findAll(String sub) {
        return jdbc.sql("""
                select sub, system, type, state, backend_user, expires_at, connected_at, last_used_at, secret_version, access_expires_at
                from connection where sub = :sub order by system
                """)
                .param("sub", sub)
                .query(ConnectionRepository::map)
                .list();
    }

    public void delete(String sub, String system) {
        jdbc.sql("delete from connection where sub = :sub and system = :system")
                .param("sub", sub)
                .param("system", system)
                .update();
    }

    /**
     * Connections whose last use (their creation when they were never used) is before {@code cutoff}, oldest first; the
     * candidates of the cleanup of unused connections.
     */
    public List<Connection> findLastActivityBefore(Instant cutoff, int limit, int skip) {
        return jdbc.sql("""
                select sub, system, type, state, backend_user, expires_at, connected_at, last_used_at, secret_version, access_expires_at
                from connection
                where coalesce(last_used_at, connected_at) < :cutoff
                order by coalesce(last_used_at, connected_at), sub, system limit :limit offset :skip
                """)
                .param("cutoff", timestamp(cutoff))
                .param("skip", skip)
                .param("limit", limit)
                .query(ConnectionRepository::map)
                .list();
    }

    /**
     * Connected OAuth connections of the given systems whose access token stops working before {@code deadline},
     * oldest first. Rows of systems that are no longer configured would never be renewed and would crowd out the rest.
     */
    public List<Connection> findOAuthExpiringBefore(Instant deadline, Collection<String> systems, int limit) {
        if (systems.isEmpty()) {
            return List.of();
        }
        return jdbc.sql("""
                select sub, system, type, state, backend_user, expires_at, connected_at, last_used_at, secret_version, access_expires_at
                from connection
                where type = 'user-oauth' and state = 'connected' and system in (:systems) and access_expires_at < :deadline
                order by access_expires_at limit :limit
                """)
                .param("deadline", timestamp(deadline))
                .param("systems", systems)
                .param("limit", limit)
                .query(ConnectionRepository::map)
                .list();
    }

    /**
     * Moves the row to a new secret version only if it still points at {@code expectedVersion} and is connected:
     * a disconnect or a newer connection that happened while a refresh was in flight wins over the refresh.
     */
    public boolean switchSecretVersion(String sub, String system, String expectedVersion, String newVersion,
            Instant accessExpiresAt, Instant now) {
        return jdbc.sql("""
                update connection set secret_version = :newVersion, access_expires_at = :accessExpiresAt, updated_at = :now
                where sub = :sub and system = :system and state = 'connected' and secret_version is not distinct from :expected
                """)
                .param("newVersion", newVersion)
                .param("accessExpiresAt", timestamp(accessExpiresAt))
                .param("now", timestamp(now))
                .param("sub", sub)
                .param("system", system)
                .param("expected", expectedVersion)
                .update() == 1;
    }

    /** Same guard as {@link #switchSecretVersion}: a state change only for the version the caller read. */
    public boolean setStateIfVersion(String sub, String system, String expectedVersion, Connection.StoredState state, Instant now) {
        return jdbc.sql("""
                update connection set state = :state, updated_at = :now
                where sub = :sub and system = :system and state = 'connected' and secret_version is not distinct from :expected
                """)
                .param("state", state.name().toLowerCase(Locale.ROOT))
                .param("now", timestamp(now))
                .param("sub", sub)
                .param("system", system)
                .param("expected", expectedVersion)
                .update() == 1;
    }

    public void touch(String sub, String system, Instant lastUsedAt) {
        jdbc.sql("update connection set last_used_at = :lastUsedAt where sub = :sub and system = :system")
                .param("lastUsedAt", timestamp(lastUsedAt))
                .param("sub", sub)
                .param("system", system)
                .update();
    }

    private static Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }

    private static Connection map(ResultSet rs, int row) throws SQLException {
        CredentialType credentialType = CredentialType.fromWire(rs.getString("type"))
                .orElseThrow(() -> new SQLException("unknown credential type in row"));
        return new Connection(rs.getString("sub"), rs.getString("system"), credentialType,
                Connection.StoredState.valueOf(rs.getString("state").toUpperCase(Locale.ROOT)),
                rs.getString("backend_user"), instant(rs, "expires_at"), instant(rs, "connected_at"),
                instant(rs, "last_used_at"), rs.getString("secret_version"), instant(rs, "access_expires_at"));
    }
}
