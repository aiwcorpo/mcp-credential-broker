package pl.aiwcorpo.mcp.broker.tracing;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class TracingEnvironmentTest {

    private MockEnvironment environment(String... properties) {
        MockEnvironment environment = new MockEnvironment();
        for (int i = 0; i < properties.length; i += 2) {
            environment.setProperty(properties[i], properties[i + 1]);
        }
        new TracingEnvironment().postProcessEnvironment(environment, null);
        return environment;
    }

    @Test
    void tracingIsOffWhenNoEndpointIsGiven() {
        MockEnvironment environment = environment();
        assertThat(environment.getProperty("management.tracing.export.enabled")).isEqualTo("false");
        assertThat(environment.getProperty("management.opentelemetry.enabled")).isEqualTo("false");
        assertThat(environment.getProperty("management.opentelemetry.tracing.export.otlp.endpoint")).isNull();
    }

    @Test
    void aBlankEndpointKeepsTracingOff() {
        assertThat(environment("MCP_OTLP_ENDPOINT", "  ").getProperty("management.tracing.export.enabled")).isEqualTo("false");
    }

    @Test
    void anEndpointTurnsTracingOnAndIsPassedToTheExporter() {
        MockEnvironment environment = environment("MCP_OTLP_ENDPOINT", "http://collector:4318/v1/traces");
        assertThat(environment.getProperty("management.tracing.export.enabled")).isEqualTo("true");
        assertThat(environment.getProperty("management.opentelemetry.enabled")).isEqualTo("true");
        assertThat(environment.getProperty("management.opentelemetry.tracing.export.otlp.endpoint"))
                .isEqualTo("http://collector:4318/v1/traces");
    }
}
