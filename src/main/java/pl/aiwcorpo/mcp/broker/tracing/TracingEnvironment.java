package pl.aiwcorpo.mcp.broker.tracing;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/**
 * Tracing is off unless {@code MCP_OTLP_ENDPOINT} (the full OTLP/HTTP traces URL, for example
 * {@code http://collector:4318/v1/traces}) is set, so the operator sets one value. The values are defaults of the lowest priority:
 * an explicit {@code management.*} property (or {@code MANAGEMENT_TRACING_EXPORT_ENABLED=false}, {@code MANAGEMENT_OPENTELEMETRY_ENABLED=false})
 * still wins in either direction. {@code management.tracing.export.enabled} gates the Micrometer side (the spans of requests),
 * {@code management.opentelemetry.enabled} the OpenTelemetry SDK and exporter. {@code management.tracing.enabled} is not used: Spring Boot 4
 * ignores it. Both switches are written explicitly, also as {@code false}, because Spring Boot enables tracing by itself when the libraries
 * are on the classpath (and then adds a correlation id block to every log line), and a placeholder in application.yml cannot turn a URL
 * into a boolean.
 */
public final class TracingEnvironment implements EnvironmentPostProcessor {

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String endpoint = environment.getProperty("MCP_OTLP_ENDPOINT", "").trim();
        Map<String, Object> defaults = new LinkedHashMap<>();
        String on = Boolean.toString(!endpoint.isEmpty());
        defaults.put("management.tracing.export.enabled", on);
        defaults.put("management.opentelemetry.enabled", on);
        if (!endpoint.isEmpty()) {
            defaults.put("management.opentelemetry.tracing.export.otlp.endpoint", endpoint);
        }
        environment.getPropertySources().addLast(new MapPropertySource("brokerTracing", defaults));
    }
}
