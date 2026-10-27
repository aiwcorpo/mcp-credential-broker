package pl.aiwcorpo.mcp.broker.credential;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
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
                select sub, system, type, state, backend_user, expires_at, connected_at, last_used_at
                from connection where sub = :sub and system = :system
                """)
                .param("sub", sub)
                .param("system", system)
                .query(ConnectionRepository::map)
                .optional();
    }

    public void upsert(Connection connection, Instant now) {
        jdbc.sql("""
                insert into connection (sub, system, type, state, backend_user, expires_at, connected_at, last_used_at, updated_at)
                values (:sub, :system, :type, :state, :backendUser, :expiresAt, :connectedAt, :lastUsedAt, :now)
                on conflict (sub, system) do update set
                    type = excluded.type, state = excluded.state, backend_user = excluded.backend_user,
                    expires_at = excluded.expires_at, connected_at = excluded.connected_at,
                    last_used_at = excluded.last_used_at, updated_at = excluded.updated_at
                """)
                .param("sub", connection.sub())
                .param("system", connection.system())
                .param("type", connection.type().wire())
                .param("state", connection.state().name().toLowerCase(Locale.ROOT))
                .param("backendUser", connection.backendUser())
                .param("expiresAt", timestamp(connection.expiresAt()))
                .param("connectedAt", timestamp(connection.connectedAt()))
                .param("lastUsedAt", timestamp(connection.lastUsedAt()))
                .param("now", timestamp(now))
                .update();
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
                instant(rs, "last_used_at"));
    }
}
