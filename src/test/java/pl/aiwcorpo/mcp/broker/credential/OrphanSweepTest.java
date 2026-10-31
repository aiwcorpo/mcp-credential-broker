package pl.aiwcorpo.mcp.broker.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.authenticator.AuthenticatorService;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.oauth.OAuthFlowStore;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;

/** The guards of the sweep of orphaned stored values: it must not turn a bad read of the rows into mass deletion. */
class OrphanSweepTest {

    private static final Instant NOW = Instant.parse("2026-10-31T12:00:00Z");
    private static final Instant OLD = NOW.minus(Duration.ofDays(2));

    private final ConnectionRepository connections = mock(ConnectionRepository.class);
    private final SecretStore secrets = mock(SecretStore.class);
    private final OAuthService oauth = mock(OAuthService.class);
    private final List<SecretStore.Stored> listed = new ArrayList<>();

    @BeforeEach
    void stored() {
        when(secrets.listStored()).thenReturn(listed);
        when(oauth.isPlainSecretSystem("jira")).thenReturn(true);
        when(oauth.isPlainSecretSystem("gitlab")).thenReturn(false);
    }

    private OffboardingService service(boolean delete, int maxDeletes, double maxFraction) {
        BrokerProperties.Retention retention = new BrokerProperties.Retention(Duration.ofDays(180), Duration.ofHours(1), 100,
                Duration.ofHours(1), Duration.ofHours(6), delete, maxDeletes, maxFraction);
        return new OffboardingService(connections, secrets, mock(InvalidationPublisher.class), oauth, mock(OAuthFlowStore.class),
                mock(AuthenticatorService.class), new AuditLog("mcp-credential-broker", Clock.fixed(NOW, ZoneOffset.UTC)),
                Clock.fixed(NOW, ZoneOffset.UTC), retention);
    }

    private void values(int referenced, int orphans, String system) {
        Set<String> paths = new java.util.HashSet<>();
        for (int i = 0; i < referenced; i++) {
            listed.add(new SecretStore.Stored("h" + i, "jira", "v", OLD));
            paths.add("h" + i + "/jira/v");
        }
        for (int i = 0; i < orphans; i++) {
            listed.add(new SecretStore.Stored("o" + i, system, "v", OLD));
        }
        when(connections.referencedSecretPaths()).thenReturn(paths);
    }

    @Test
    void byDefaultItOnlyReports() {
        values(20, 1, "jira");
        OffboardingService.OrphanSweep result = service(false, 50, 0.2).sweepOrphanSecrets();
        assertThat(result.orphans()).isEqualTo(1);
        assertThat(result.deleted()).isZero();
        verify(secrets, never()).deleteStored(any());
    }

    @Test
    void noReferencesAtAllWhileTheStoreHoldsValuesDeletesNothing() {
        values(0, 5, "jira");
        OffboardingService.OrphanSweep result = service(true, 50, 1.0).sweepOrphanSecrets();
        assertThat(result.refusedBecause()).isEqualTo("no_references");
        verify(secrets, never()).deleteStored(any());
    }

    @Test
    void aLargeShareOfOrphansDeletesNothing() {
        values(10, 10, "jira");
        OffboardingService.OrphanSweep result = service(true, 50, 0.2).sweepOrphanSecrets();
        assertThat(result.refusedBecause()).isEqualTo("too_many");
        verify(secrets, never()).deleteStored(any());
    }

    @Test
    void deletionIsCappedPerRunAndSkipsOAuthSystemsAndFreshValues() {
        values(100, 3, "jira");
        values(0, 0, "jira");
        listed.add(new SecretStore.Stored("g", "gitlab", "v", OLD));
        listed.add(new SecretStore.Stored("fresh", "jira", "v", NOW));
        Set<String> paths = new java.util.HashSet<>();
        for (int i = 0; i < 100; i++) {
            paths.add("h" + i + "/jira/v");
        }
        when(connections.referencedSecretPaths()).thenReturn(paths);

        OffboardingService.OrphanSweep result = service(true, 2, 0.5).sweepOrphanSecrets();

        assertThat(result.deleted()).isEqualTo(2);
        verify(secrets, never()).deleteStored(new SecretStore.Stored("g", "gitlab", "v", OLD));
        verify(secrets, never()).deleteStored(new SecretStore.Stored("fresh", "jira", "v", NOW));
    }
}
