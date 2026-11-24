package pl.aiwcorpo.mcp.broker.system;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.dao.DataAccessResourceFailureException;

import pl.aiwcorpo.mcp.broker.api.SystemAdminRequest;
import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.support.AuditLines;

@ExtendWith(OutputCaptureExtension.class)
class SystemAdminServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-27T12:00:00Z");
    private static final String RID = "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f";

    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final SystemRepository repository = mock(SystemRepository.class);

    @Test
    void aFailingLookupForTheMfaExemptionLeavesTheCallerWithTheAuditedStepUp(CapturedOutput output) {
        when(repository.find(anyString())).thenThrow(new DataAccessResourceFailureException("database down"));
        SystemAdminService service = new SystemAdminService(repository, mock(SystemRegistry.class), null, null, null, null, null, null,
                new AuditLog("mcp-credential-broker", clock), clock, false, URI.create("https://idp.test/token"), null,
                new BrokerProperties.BffToken("https://idp.test", URI.create("https://idp.test/jwks"), "mcp-credential-broker",
                        Set.of("mcp-portal-bff"), "preferred_username", null, Set.of(), Set.of("otp")),
                new BrokerProperties.TokenExchangePolicy(List.of()), false, null);
        Caller.PortalUser staleAdmin = new Caller.PortalUser(RID, "admin-sub", "root", "mcp-portal-bff", Map.of(
                "groups", List.of("mcp-platform-admin"), "auth_time", NOW.minusSeconds(3600).getEpochSecond(), "amr", List.of("otp")));
        SystemAdminRequest turnOff = new SystemAdminRequest("https://desk.test", "generic-rest", null, null,
                List.of(CredentialType.SERVICE_ACCOUNT), CredentialType.SERVICE_ACCOUNT, CredentialScheme.BEARER, null, null, null, null,
                null, null, false);

        assertThatThrownBy(() -> service.put(staleAdmin, "desk", turnOff, "\"abcdefgh12\"", null))
                .isInstanceOfSatisfying(SystemAdminException.class, e -> {
                    assertThat(e.status()).isEqualTo(401);
                    assertThat(e.error()).isEqualTo("step_up_required");
                });

        assertThat(AuditLines.of(output, RID)).singleElement()
                .satisfies(event -> assertThat(event.path("reason").stringValue()).isEqualTo("step_up_required"));
    }
}
