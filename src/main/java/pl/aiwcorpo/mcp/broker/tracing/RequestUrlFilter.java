package pl.aiwcorpo.mcp.broker.tracing;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationFilter;

/**
 * Spring Boot records the literal request path as {@code http.url}. Paths here carry identifiers (a target system's name and a user's
 * {@code sub}, as in {@code /v1/connections/{system}/secret}), so only the route template (tag {@code uri}) stays on the span.
 */
public final class RequestUrlFilter implements ObservationFilter {

    @Override
    public Observation.Context map(Observation.Context context) {
        context.removeHighCardinalityKeyValue("http.url");
        return context;
    }
}
