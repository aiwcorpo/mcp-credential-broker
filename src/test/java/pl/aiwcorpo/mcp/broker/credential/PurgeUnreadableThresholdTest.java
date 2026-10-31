package pl.aiwcorpo.mcp.broker.credential;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.authenticator.AuthenticatorService;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.oauth.OAuthFlowStore;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;

/** One unreadable stored value is damage and the purge goes on; several in one purge look like a wrong key and it stops. */
class PurgeUnreadableThresholdTest {

    private static final Instant NOW = Instant.parse("2026-10-31T12:00:00Z");

    private final ConnectionRepository connections = mock(ConnectionRepository.class);
    private final SecretStore secrets = mock(SecretStore.class);
    private final OAuthService oauth = mock(OAuthService.class);

    private Connection connection(String system) {
        return new Connection("u", system, CredentialType.USER_OAUTH, Connection.StoredState.CONNECTED, "alice", null, NOW, null, "v", NOW);
    }

    private OffboardingService service() {
        BrokerProperties.Retention retention = new BrokerProperties.Retention(Duration.ofDays(180), Duration.ofHours(1), 100,
                Duration.ofHours(1), Duration.ofHours(6), false, 50, 0.2, Duration.ofMinutes(30));
        when(connections.find(any(), any())).thenAnswer(call -> java.util.Optional.of(connection(call.getArgument(1))));
        when(oauth.underRefreshLock(any(), any(), any())).thenAnswer(call -> ((Supplier<Object>) call.getArgument(2)).get());
        when(oauth.revokeAtProvider(any(), any())).thenAnswer(call -> {
            ((Runnable) call.getArgument(1)).run();
            return false;
        });
        return new OffboardingService(connections, secrets, mock(InvalidationPublisher.class), oauth, mock(OAuthFlowStore.class),
                mock(AuthenticatorService.class), new AuditLog("mcp-credential-broker", Clock.fixed(NOW, ZoneOffset.UTC)),
                Clock.fixed(NOW, ZoneOffset.UTC), retention);
    }

    @Test
    void oneUnreadableValueDoesNotStopThePurge() {
        when(connections.findAll("u")).thenReturn(List.of(connection("gitlab")), List.of());
        service().purge("0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f", "u");
        verify(connections).delete("u", "gitlab");
    }

    @Test
    void severalUnreadableValuesStopItBeforeTheyAreDeleted() {
        when(connections.findAll("u")).thenReturn(
                List.of(connection("a"), connection("b"), connection("c"), connection("d"), connection("e")));
        assertThatThrownBy(() -> service().purge("0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f", "u"))
                .isInstanceOf(SecretStoreUnavailableException.class);
        verify(connections, never()).delete("u", "d");
        verify(connections, never()).delete("u", "e");
        verify(secrets, never()).deleteAllOf(any());
    }
}
