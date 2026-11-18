package pl.aiwcorpo.mcp.broker.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.InternalJwtClaims;
import pl.aiwcorpo.mcp.broker.auth.SubjectTokenVerifier;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;
import pl.aiwcorpo.mcp.broker.support.MutableClock;
import pl.aiwcorpo.mcp.broker.system.SystemAdapters;
import pl.aiwcorpo.mcp.broker.system.SystemDefinition;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import pl.aiwcorpo.mcp.broker.system.UpstreamLimits;
import pl.aiwcorpo.mcp.broker.system.SystemRegistryRefreshJob;
import pl.aiwcorpo.mcp.broker.system.SystemRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import tools.jackson.databind.json.JsonMapper;

/** A resolve that reads no row of its own trusts the system list only while it keeps being reloaded. */
class SystemRegistryTest {

    private static final String RID = "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f";

    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-27T12:00:00Z"));
    private final SystemRepository repository = mock(SystemRepository.class);
    private final ServiceAccountKeys keys = mock(ServiceAccountKeys.class);

    @Test
    void aServiceAccountIsNotResolvedFromASystemListThatStoppedReloading() {
        when(repository.findAll()).thenReturn(List.of(new SystemDefinition("svc", URI.create("https://svc.test"), "generic-rest", null,
                List.of(CredentialType.SERVICE_ACCOUNT), CredentialType.SERVICE_ACCOUNT, CredentialScheme.BEARER, null, null,
                Duration.ofSeconds(1), null, null, null, "etag-svc", "revision-svc")));
        when(keys.read("svc", CredentialScheme.BEARER)).thenReturn(new ServiceAccountKeys.Key(SecretValue.of("dummy-key"), null));
        SystemAdapters adapters = new SystemAdapters(HttpClient.newHttpClient(), JsonMapper.builder().build(),
                mock(OAuthClientSecrets.class), keys, clock, new SimpleMeterRegistry(),
                new BrokerProperties.TokenExchangePolicy(List.of("*")), new UpstreamLimits(20, Duration.ofSeconds(60)));
        SystemRegistry registry = new SystemRegistry(repository, adapters, clock, Duration.ofMinutes(1));
        CredentialService service = new CredentialService(registry, mock(ConnectionRepository.class), mock(SecretStore.class),
                mock(InvalidationPublisher.class), mock(OAuthService.class), mock(SubjectTokenVerifier.class),
                new AuditLog("mcp-credential-broker", clock), clock, 60, Duration.ofDays(7),
                new LostSecretSignal(clock, new SimpleMeterRegistry()));
        assertThat(service.resolve(gateway(), "svc", null, null).value().reveal()).isEqualTo("dummy-key");

        when(repository.findAll()).thenThrow(new DataAccessResourceFailureException("database down"));
        SystemRegistryRefreshJob job = new SystemRegistryRefreshJob(registry);
        for (int run = 0; run < 3; run++) {
            clock.advance(Duration.ofSeconds(30));
            job.run();
        }

        assertThatThrownBy(() -> service.resolve(gateway(), "svc", null, null))
                .isInstanceOf(DataAccessResourceFailureException.class);
    }

    private static Caller.Gateway gateway() {
        return new Caller.Gateway(RID, new InternalJwtClaims("alice-sub", "alice", List.of(), "claude-code", "get_issue",
                RID, 7L, "jti-1", false));
    }
}
