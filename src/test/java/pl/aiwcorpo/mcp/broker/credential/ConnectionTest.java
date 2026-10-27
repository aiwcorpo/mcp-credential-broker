package pl.aiwcorpo.mcp.broker.credential;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;

class ConnectionTest {

    private static final Instant NOW = Instant.parse("2026-10-27T12:00:00Z");
    private static final Duration WEEK = Duration.ofDays(7);

    @Test
    void statusFollowsExpiryAndStoredState() {
        assertThat(connection(Connection.StoredState.CONNECTED, null).status(NOW, WEEK)).isEqualTo(ConnectionStatus.CONNECTED);
        assertThat(connection(Connection.StoredState.CONNECTED, NOW.plus(Duration.ofDays(8))).status(NOW, WEEK))
                .isEqualTo(ConnectionStatus.CONNECTED);
        assertThat(connection(Connection.StoredState.CONNECTED, NOW.plus(Duration.ofDays(6))).status(NOW, WEEK))
                .isEqualTo(ConnectionStatus.EXPIRING);
        assertThat(connection(Connection.StoredState.CONNECTED, NOW).status(NOW, WEEK)).isEqualTo(ConnectionStatus.EXPIRED);
        assertThat(connection(Connection.StoredState.REVOKED, null).status(NOW, WEEK)).isEqualTo(ConnectionStatus.REVOKED);
        assertThat(connection(Connection.StoredState.ERROR, null).status(NOW, WEEK)).isEqualTo(ConnectionStatus.ERROR);
    }

    @Test
    void onlyConnectedAndExpiringAreUsable() {
        assertThat(ConnectionStatus.CONNECTED.usable()).isTrue();
        assertThat(ConnectionStatus.EXPIRING.usable()).isTrue();
        assertThat(ConnectionStatus.EXPIRED.usable()).isFalse();
        assertThat(ConnectionStatus.REVOKED.usable()).isFalse();
        assertThat(ConnectionStatus.ERROR.usable()).isFalse();
    }

    private static Connection connection(Connection.StoredState state, Instant expiresAt) {
        return new Connection("sub", "jira", CredentialType.USER_SECRET, state, "alice", expiresAt, NOW, null);
    }
}
