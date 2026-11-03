package pl.aiwcorpo.mcp.broker.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** A token that cannot be checked because the keys or the replay store are down: event, names and outcome of CC-197. */
@ExtendWith(OutputCaptureExtension.class)
class CallerAuthenticationFilterOutageTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-03T10:00:00Z"), ZoneOffset.UTC);

    private final InternalJwtVerifier gatewayTokens = mock(InternalJwtVerifier.class);

    private JsonNode outageEvent(RuntimeException failure, String vector, CapturedOutput output) throws Exception {
        when(gatewayTokens.verify(anyString(), any(), anyBoolean(), any())).thenThrow(failure);
        CallerAuthenticationFilter filter = new CallerAuthenticationFilter(gatewayTokens, mock(BffTokenVerifier.class),
                new AuditLog("mcp-credential-broker", CLOCK), JsonMapper.builder().build(), CLOCK, 65536);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/v1/credentials/resolve");
        request.addHeader("Authorization", "Bearer a.b.c");
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal("CN=mcp-gateway"));
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[] {certificate});
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(503);
        List<JsonNode> events = AuditLines.of(output, response.getHeader("X-Request-Id"));
        assertThat(events).singleElement().satisfies(event -> {
            JsonNode published = Contracts.json("test-vectors/audit-events/" + vector).path("event");
            for (String field : List.of("component", "componentId", "event", "reason", "outcome", "errorCode")) {
                assertThat(event.path(field)).as(field).isEqualTo(published.path(field));
            }
            assertThat(event.has("server")).as("no system: the failure is not about one").isFalse();
        });
        return events.getFirst();
    }

    @Test
    void unavailableKeysAreAuthenticationJwksUnavailableDenied(CapturedOutput output) throws Exception {
        outageEvent(new KeySourceUnavailableException("no keys"), "broker-authentication-jwks-unavailable.json", output);
    }

    @Test
    void unavailableReplayStoreIsAuthenticationReplayStoreUnavailableDenied(CapturedOutput output) throws Exception {
        outageEvent(new ReplayGuardUnavailableException("no redis"), "broker-authentication-denied-replay-store-unavailable.json", output);
    }
}
