package pl.aiwcorpo.mcp.broker.tracing;

import org.springframework.beans.factory.config.BeanPostProcessor;

import io.opentelemetry.sdk.trace.export.SpanExporter;

/** Wraps every span exporter of the context, so that no exporter Spring Boot or an operator adds bypasses the redaction. */
public final class RedactingSpanExporters implements BeanPostProcessor {

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (bean instanceof SpanExporter exporter && !(bean instanceof RedactingSpanExporter)) {
            return new RedactingSpanExporter(exporter);
        }
        return bean;
    }
}
