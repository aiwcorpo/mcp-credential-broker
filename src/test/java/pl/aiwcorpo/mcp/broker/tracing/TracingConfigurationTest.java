package pl.aiwcorpo.mcp.broker.tracing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

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

import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import pl.aiwcorpo.mcp.broker.support.TraceCollectorStub;

/** Pins the Spring Boot property names the documentation tells operators to use, against the autoconfiguration of the Boot in the pom. */
class TracingConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(
            ObservationAutoConfiguration.class, MicrometerTracingAutoConfiguration.class, NoopTracerAutoConfiguration.class,
            OpenTelemetrySdkAutoConfiguration.class, OpenTelemetryTracingAutoConfiguration.class, OtlpTracingAutoConfiguration.class));

    private final ApplicationContextRunner withEnvironment = runner.withInitializer(
            context -> new TracingEnvironment().postProcessEnvironment(context.getEnvironment(), null));

    private TraceCollectorStub collector;

    @BeforeEach
    void startCollector() throws Exception {
        collector = new TraceCollectorStub();
    }

    @AfterEach
    void stopCollector() {
        collector.close();
    }

    @Test
    void withTracingOffThereIsNoSdkNoCurrentSpanAndNothingIsSent() {
        runner.withPropertyValues("management.tracing.export.enabled=false", "management.opentelemetry.enabled=false",
                "management.opentelemetry.tracing.export.otlp.endpoint=" + collector.endpoint()).run(context -> {
                    assertThat(context).doesNotHaveBean(SdkTracerProvider.class);
                    assertThat(context).doesNotHaveBean(io.opentelemetry.sdk.trace.SpanProcessor.class);
                    assertThat(context.getBean(Tracer.class).currentSpan()).isNull();
                    context.getBean(Tracer.class).nextSpan().name("ignored").start().end();
                    assertThat(collector.bodies()).isEmpty();
                });
    }

    @Test
    void withTracingOnASpanIsSentToTheConfiguredEndpointWithTheServiceName() {
        runner.withPropertyValues("management.tracing.export.enabled=true", "management.opentelemetry.enabled=true", "management.tracing.sampling.probability=1.0",
                "management.opentelemetry.tracing.export.schedule-delay=100ms", "spring.application.name=mcp-credential-broker",
                "management.opentelemetry.tracing.export.otlp.endpoint=" + collector.endpoint()).run(context -> {
                    Span span = context.getBean(Tracer.class).nextSpan().name("probe").start();
                    span.end();
                    await().atMost(Duration.ofSeconds(10)).until(() -> !collector.bodies().isEmpty());
                    String body = new String(collector.bodies().getFirst(), java.nio.charset.StandardCharsets.ISO_8859_1);
                    assertThat(body).contains("probe").contains("mcp-credential-broker");
                });
    }

    @Test
    void theEndpointAloneTurnsTheSdkOnAndSpansReachTheCollector() {
        withEnvironment.withPropertyValues("MCP_OTLP_ENDPOINT=" + collector.endpoint(), "management.tracing.sampling.probability=1.0",
                "management.opentelemetry.tracing.export.schedule-delay=100ms").run(context -> {
                    assertThat(context).hasSingleBean(SdkTracerProvider.class);
                    context.getBean(Tracer.class).nextSpan().name("probe").start().end();
                    await().atMost(Duration.ofSeconds(10)).until(() -> !collector.bodies().isEmpty());
                });
    }

    @Test
    void withNoEndpointThereIsNoSdkAndNothingIsSent() {
        withEnvironment.withPropertyValues("management.opentelemetry.tracing.export.otlp.endpoint=" + collector.endpoint()).run(context -> {
            assertThat(context).doesNotHaveBean(SdkTracerProvider.class);
            context.getBean(Tracer.class).nextSpan().name("ignored").start().end();
            assertThat(collector.bodies()).isEmpty();
        });
    }

    @Test
    void theDocumentedOpenTelemetrySwitchTurnsTracingOffEvenWithAnEndpoint() {
        withEnvironment.withPropertyValues("MCP_OTLP_ENDPOINT=" + collector.endpoint(), "management.opentelemetry.enabled=false",
                "management.tracing.sampling.probability=1.0").run(context -> {
                    assertThat(context).doesNotHaveBean(SdkTracerProvider.class);
                    context.getBean(Tracer.class).nextSpan().name("ignored").start().end();
                    assertThat(collector.bodies()).isEmpty();
                });
    }

    @Test
    void theDocumentedExportSwitchTurnsTracingOffEvenWithAnEndpoint() throws Exception {
        withEnvironment.withPropertyValues("MCP_OTLP_ENDPOINT=" + collector.endpoint(), "management.tracing.export.enabled=false",
                "management.tracing.sampling.probability=1.0", "management.opentelemetry.tracing.export.schedule-delay=100ms").run(context -> {
                    context.getBean(Tracer.class).nextSpan().name("ignored").start().end();
                    Thread.sleep(500);
                    assertThat(collector.bodies()).isEmpty();
                });
    }

    @Test
    void theRemovedSwitchManagementTracingEnabledDoesNothing() {
        withEnvironment.withPropertyValues("MCP_OTLP_ENDPOINT=" + collector.endpoint(), "management.tracing.enabled=false",
                "management.tracing.sampling.probability=1.0").run(context -> assertThat(context).hasSingleBean(SdkTracerProvider.class));
    }
}
