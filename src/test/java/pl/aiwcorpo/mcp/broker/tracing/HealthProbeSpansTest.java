package pl.aiwcorpo.mcp.broker.tracing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.http.server.observation.ServerRequestObservationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import io.micrometer.observation.Observation;
import io.micrometer.tracing.exporter.FinishedSpan;

class HealthProbeSpansTest {

    private final HealthProbeSpans spans = new HealthProbeSpans();

    private boolean marked(String servletPath) {
        return marked(servletPath, servletPath);
    }

    private boolean marked(String requestUri, String servletPath) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
        request.setServletPath(servletPath);
        Observation.Context context = spans.map(new ServerRequestObservationContext(request, new MockHttpServletResponse()));
        return context.getHighCardinalityKeyValues().stream().anyMatch(kv -> kv.getKey().equals(HealthProbeSpans.MARK));
    }

    private boolean exportable(Map<String, String> tags) {
        FinishedSpan span = mock(FinishedSpan.class);
        when(span.getTags()).thenReturn(tags);
        return spans.isExportable(span);
    }

    @Test
    void theHealthEndpointAndItsSubPathsAreMarked() {
        assertThat(marked("/actuator/health")).isTrue();
        assertThat(marked("/actuator/health/liveness")).isTrue();
        assertThat(marked("/actuator/health/readiness/db")).isTrue();
    }

    @Test
    void nothingThatOnlyStartsWithTheHealthPathIsMarked() {
        for (String path : new String[] {"/actuator/healthx", "/actuator/health-check", "/actuator/info", "/actuator", "/mcp",
                "/s/x/mcp/actuator/health", "/actuator/prometheus", "/health", "/"}) {
            assertThat(marked(path)).as(path).isFalse();
        }
    }

    @Test
    void aPathThatOnlyNormalisesToTheHealthPathIsNotMarked() {
        String health = "/actuator/health";
        for (String uri : new String[] {"//actuator/health", "/actuator//health", "/x/../actuator/health", "/x/..;/actuator/health",
                "/actuator/./health", "/actuator/health;a=b", "/actuator/%68ealth", "/actuator/%2e/health", "/actuator/health/",
                "/v1/../actuator/health", "/s/x/mcp/../../../actuator/health"}) {
            assertThat(marked(uri, health)).as(uri).isFalse();
        }
        assertThat(marked("/actuator/health/liveness;a=b", "/actuator/health/liveness")).isFalse();
    }

    @Test
    void theMarkIsHighCardinalityAndSoNeverBecomesAMetricTag() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
        request.setServletPath("/actuator/health");
        Observation.Context context = spans.map(new ServerRequestObservationContext(request, new MockHttpServletResponse()));
        assertThat(context.getLowCardinalityKeyValues().stream().map(kv -> kv.getKey())).doesNotContain(HealthProbeSpans.MARK);
    }

    @Test
    void anotherKindOfObservationIsLeftAlone() {
        Observation.Context context = new Observation.Context();
        assertThat(spans.map(context).getHighCardinalityKeyValues()).isEmpty();
    }

    @Test
    void onlyAMarkedSpanIsHeldBack() {
        assertThat(exportable(Map.of(HealthProbeSpans.MARK, "true", "uri", "UNKNOWN"))).isFalse();
        assertThat(exportable(Map.of("uri", "/actuator/healthx"))).isTrue();
        assertThat(exportable(Map.of())).isTrue();
    }
}
