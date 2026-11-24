package pl.aiwcorpo.mcp.broker.tracing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.micrometer.observation.autoconfigure.ObservationAutoConfiguration;
import org.springframework.boot.micrometer.tracing.autoconfigure.MicrometerTracingAutoConfiguration;
import org.springframework.boot.micrometer.tracing.autoconfigure.NoopTracerAutoConfiguration;
import org.springframework.boot.micrometer.tracing.opentelemetry.autoconfigure.OpenTelemetryTracingAutoConfiguration;
import org.springframework.boot.micrometer.tracing.opentelemetry.autoconfigure.otlp.OtlpTracingAutoConfiguration;
import org.springframework.boot.opentelemetry.autoconfigure.OpenTelemetrySdkAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import io.micrometer.common.KeyValue;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import pl.aiwcorpo.mcp.broker.support.TraceCollectorStub;

class SpanRedactionTest {

    private static final String MARKER = "BACKEND-BODY-MARKER-91c2";
    private static final String SECRET_QUERY = "token=QUERY-SECRET-77f1";

    private final ApplicationContextRunner runner = new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(
            ObservationAutoConfiguration.class, MicrometerTracingAutoConfiguration.class, NoopTracerAutoConfiguration.class,
            OpenTelemetrySdkAutoConfiguration.class, OpenTelemetryTracingAutoConfiguration.class, OtlpTracingAutoConfiguration.class))
            .withBean(RedactingSpanExporters.class, RedactingSpanExporters::new)
            .withBean(RequestUrlFilter.class, RequestUrlFilter::new);

    private TraceCollectorStub collector;

    @BeforeEach
    void startCollector() throws Exception {
        collector = new TraceCollectorStub();
    }

    @AfterEach
    void stopCollector() {
        collector.close();
    }

    private String exportedAfter(Observation.Context context, Throwable failure) {
        StringBuilder exported = new StringBuilder();
        runner.withPropertyValues("management.tracing.export.enabled=true", "management.opentelemetry.enabled=true",
                "management.tracing.sampling.probability=1.0", "management.opentelemetry.tracing.export.schedule-delay=100ms",
                "management.opentelemetry.tracing.export.otlp.endpoint=" + collector.endpoint()).run(application -> {
                    Observation observation = Observation.start("http.client.requests", () -> context, application.getBean(ObservationRegistry.class));
                    if (failure != null) {
                        observation.error(failure);
                    }
                    observation.stop();
                    await().atMost(Duration.ofSeconds(10)).until(() -> !collector.bodies().isEmpty());
                    collector.bodies().forEach(body -> exported.append(new String(body, StandardCharsets.ISO_8859_1)));
                });
        return exported.toString();
    }

    @Test
    void anErrorSpanKeepsTheExceptionClassAndNeitherTheMessageNorTheStackTrace() {
        Observation.Context context = new Observation.Context();
        String exported = exportedAfter(context, new IllegalStateException("backend answered 502: " + MARKER + " from https://backend/x?" + SECRET_QUERY));
        assertThat(exported).contains("java.lang.IllegalStateException").doesNotContain(MARKER).doesNotContain("QUERY-SECRET")
                .doesNotContain("backend answered").doesNotContain("SpanRedactionTest");
    }

    @Test
    void theUrlAttributesAndTheQueryOfTheUriTagNeverLeaveTheProcess() {
        Observation.Context context = new Observation.Context();
        context.addLowCardinalityKeyValue(KeyValue.of("uri", "https://user:pw-9d3@backend/items?" + SECRET_QUERY));
        context.addHighCardinalityKeyValue(KeyValue.of("http.url", "https://backend/items?" + SECRET_QUERY));
        context.addHighCardinalityKeyValue(KeyValue.of("url.full", "https://backend/items?" + SECRET_QUERY));
        context.addHighCardinalityKeyValue(KeyValue.of("http.target", "/items?" + SECRET_QUERY));
        String exported = exportedAfter(context, null);
        assertThat(exported).contains("uri").contains(UriLabel.UNKNOWN).doesNotContain("QUERY-SECRET").doesNotContain("pw-9d3")
                .doesNotContain("http.url").doesNotContain("url.full").doesNotContain("http.target");
    }

    @Test
    void aCallToAnotherSystemKeepsItsUriTagOnlyWhenItIsATemplate() {
        io.micrometer.observation.transport.SenderContext<Object> concatenated = new io.micrometer.observation.transport.SenderContext<>((c, k, v) -> { });
        concatenated.addLowCardinalityKeyValue(KeyValue.of("uri", "/rest/api/2/issue/PROJ-7431"));
        io.micrometer.observation.transport.SenderContext<Object> template = new io.micrometer.observation.transport.SenderContext<>((c, k, v) -> { });
        template.addLowCardinalityKeyValue(KeyValue.of("uri", "/rest/api/2/issue/{key}"));
        assertThat(new RequestUrlFilter().map(concatenated).getLowCardinalityKeyValue("uri").getValue()).isEqualTo(UriLabel.UNKNOWN);
        assertThat(new RequestUrlFilter().map(template).getLowCardinalityKeyValue("uri").getValue()).isEqualTo("/rest/api/2/issue/{key}");
    }

    @Test
    void aTemplateKeepsItsPathAndLosesItsQueryVariables() {
        assertThat(UriLabel.of("/users/{id}/issues?state={state}&page={page}")).isEqualTo("/users/{id}/issues");
        assertThat(UriLabel.of("https://{user}:{password}@backend/items/{id}")).isEqualTo("https://backend/items/{id}");
        assertThat(UriLabel.of("/items?q=literal")).isEqualTo(UriLabel.UNKNOWN);
        assertThat(UriLabel.of("https://user:secret@backend/items")).isEqualTo(UriLabel.UNKNOWN);
        assertThat(UriLabel.of("/items#section")).isEqualTo(UriLabel.UNKNOWN);
        assertThat(UriLabel.of("none")).isEqualTo("none");
        assertThat(UriLabel.of("/s/{serverId}/mcp")).isEqualTo("/s/{serverId}/mcp");
    }
}
