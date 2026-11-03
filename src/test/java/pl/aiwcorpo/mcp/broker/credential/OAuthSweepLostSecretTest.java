package pl.aiwcorpo.mcp.broker.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.oauth.OAuthFlowStore;
import pl.aiwcorpo.mcp.broker.oauth.RateLimiter;
import pl.aiwcorpo.mcp.broker.oauth.RefreshLock;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.system.OAuthProvider;
import pl.aiwcorpo.mcp.broker.system.SystemAdapter;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;

/** The background sweep meets a connection row whose secret is gone from the store. */
@ExtendWith(OutputCaptureExtension.class)
class OAuthSweepLostSecretTest {

    private static final Instant NOW = Instant.parse("2026-11-02T10:00:00Z");

    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private final ConnectionRepository connections = mock(ConnectionRepository.class);
    private final SecretStore secrets = mock(SecretStore.class);
    private final RefreshLock lock = mock(RefreshLock.class);

    private OAuthService service() {
        SystemAdapter adapter = mock(SystemAdapter.class, withSettings().extraInterfaces(OAuthProvider.class));
        BrokerProperties.SystemConfig config = new BrokerProperties.SystemConfig(URI.create("http://gitlab.test"), "gitlab",
                List.of(CredentialType.USER_OAUTH), CredentialType.USER_OAUTH, CredentialScheme.BEARER, List.of(),
                Duration.ofSeconds(1), null, null);
        SystemRegistry.ConfiguredSystem gitlab = new SystemRegistry.ConfiguredSystem("gitlab", config, adapter);
        SystemRegistry systems = mock(SystemRegistry.class);
        when(systems.all()).thenReturn(List.of(gitlab));
        when(systems.find("gitlab")).thenReturn(Optional.of(gitlab));
        when(lock.acquire(any(), any(), any())).thenReturn(Optional.of("owner"));

        Connection due = new Connection("alice-sub", "gitlab", CredentialType.USER_OAUTH, Connection.StoredState.CONNECTED,
                "alice", null, NOW.minusSeconds(3600), null, "v1", NOW.plusSeconds(30));
        when(connections.findOAuthExpiringBefore(any(), any(), org.mockito.ArgumentMatchers.anyInt())).thenReturn(List.of(due));
        when(connections.find("alice-sub", "gitlab")).thenReturn(Optional.of(due));
        when(secrets.get(any())).thenReturn(Optional.empty());

        BrokerProperties.OAuthFlow flow = new BrokerProperties.OAuthFlow(Duration.ofMinutes(10), Duration.ofMinutes(2),
                Duration.ofMinutes(5), Duration.ofMinutes(1), Duration.ofSeconds(3), Duration.ofSeconds(60), "broker:oauth:");
        BrokerProperties.RateLimits limits = new BrokerProperties.RateLimits(10, 20, Duration.ofMinutes(1), "broker:rate:");
        return new OAuthService(systems, connections, secrets,
                new ConnectionStore(connections, secrets, mock(InvalidationPublisher.class), clock), mock(OAuthFlowStore.class),
                lock, new AuditLog("mcp-credential-broker", clock), clock, URI.create("https://portal.test/api/v1/oauth/callback"),
                flow, mock(RateLimiter.class), limits, new LostSecretSignal(clock, meters));
    }

    @Test
    void sweepCountsTheMissingSecretAndReportsItOnceInTheLog(CapturedOutput output) {
        OAuthService oauth = service();
        for (int sweep = 0; sweep < 3; sweep++) {
            assertThat(oauth.refreshDue()).isZero();
        }
        assertThat(meters.counter(LostSecretSignal.METRIC, "system", "gitlab", "place", "refresh_sweep").count()).isEqualTo(3.0);
        assertThat(meters.counter(LostSecretSignal.METRIC, "system", "gitlab", "place", "resolve").count()).isZero();
        assertThat(output.getOut().split("without a stored secret", -1).length - 1).isEqualTo(1);
        assertThat(output.getOut()).doesNotContain("no longer renewable");
    }

    @Test
    void sweepPutsTheRowInErrorAndAuditsItOnce(CapturedOutput output) {
        OAuthService oauth = service();
        when(connections.setStateIfVersion("alice-sub", "gitlab", "v1", Connection.StoredState.ERROR, NOW)).thenReturn(true, false);

        oauth.refreshDue();
        oauth.refreshDue();

        verify(connections, times(2)).setStateIfVersion("alice-sub", "gitlab", "v1", Connection.StoredState.ERROR, NOW);
        assertThat(output.getOut().lines().filter(line -> line.contains("\"reason\":\"secret_missing\"")).toList())
                .singleElement().asString().contains("\"event\":\"connection_change\"", "\"outcome\":\"error\"", "\"server\":\"mcp-gitlab\"");
    }
}
