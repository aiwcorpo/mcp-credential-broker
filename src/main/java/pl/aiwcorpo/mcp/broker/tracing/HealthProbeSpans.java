package pl.aiwcorpo.mcp.broker.tracing;

import io.micrometer.common.KeyValue;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationFilter;
import io.micrometer.tracing.exporter.FinishedSpan;
import io.micrometer.tracing.exporter.SpanExportingPredicate;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.server.observation.ServerRequestObservationContext;

/**
 * Container and Kubernetes health probes run every few seconds and would otherwise be most of the exported spans, each a trace of its
 * own. Only the span is dropped: the {@code http.server.requests} metric of the probe stays, which is why the observation itself is not
 * disabled. The decision is made on the real request path (the decoded, normalised servlet path that routing sees), because the
 * {@code uri} tag of a probe is not reliable: a request refused before it reaches a handler (no client certificate, the public port) has
 * no route template and carries {@code UNKNOWN}. As an observation filter this class marks the request with a high cardinality key (a
 * low cardinality one would become a metric tag); as a span exporting predicate it keeps the marked spans back. Only
 * {@code /actuator/health} and {@code /actuator/health/**} match, nothing that merely starts with that text.
 */
public final class HealthProbeSpans implements ObservationFilter, SpanExportingPredicate {

    static final String MARK = "mcp.health.probe";

    @Override
    public Observation.Context map(Observation.Context context) {
        if (context instanceof ServerRequestObservationContext server && isHealth(server.getCarrier())) {
            context.addHighCardinalityKeyValue(KeyValue.of(MARK, "true"));
        }
        return context;
    }

    @Override
    public boolean isExportable(FinishedSpan span) {
        return !"true".equals(span.getTags().get(MARK));
    }

    static boolean isHealth(HttpServletRequest request) {
        if (request == null) {
            return false;
        }
        String path = request.getServletPath();
        return path.equals("/actuator/health") || path.startsWith("/actuator/health/");
    }
}
