package pl.aiwcorpo.mcp.broker.tracing;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.trace.data.DelegatingSpanData;
import io.opentelemetry.sdk.trace.data.EventData;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.data.StatusData;
import io.opentelemetry.sdk.trace.export.SpanExporter;

/**
 * Last stop before a span leaves the process. The instrumentation records an exception as an event with its message and stack trace, and
 * the message of a failed HTTP call can hold the response body or the URL; the status description repeats the message. Only the exception
 * class stays. Attributes that carry a URL (full, target, query) are dropped as well, whichever instrumentation set them.
 */
public final class RedactingSpanExporter implements SpanExporter {

    private static final Set<String> URL_ATTRIBUTES = Set.of("http.url", "url.full", "http.target", "url.query", "url.path");
    private static final AttributeKey<String> EXCEPTION_TYPE = AttributeKey.stringKey("exception.type");

    private final SpanExporter delegate;

    public RedactingSpanExporter(SpanExporter delegate) {
        this.delegate = delegate;
    }

    @Override
    public CompletableResultCode export(Collection<SpanData> spans) {
        List<SpanData> redacted = new ArrayList<>(spans.size());
        for (SpanData span : spans) {
            redacted.add(redact(span));
        }
        return delegate.export(redacted);
    }

    @Override
    public CompletableResultCode flush() {
        return delegate.flush();
    }

    @Override
    public CompletableResultCode shutdown() {
        return delegate.shutdown();
    }

    @Override
    public void close() {
        delegate.close();
    }

    static SpanData redact(SpanData span) {
        return new DelegatingSpanData(span) {
            @Override
            public List<EventData> getEvents() {
                List<EventData> events = new ArrayList<>();
                for (EventData event : super.getEvents()) {
                    events.add("exception".equals(event.getName()) ? exceptionClassOnly(event) : event);
                }
                return events;
            }

            @Override
            public StatusData getStatus() {
                StatusData status = super.getStatus();
                return status.getDescription().isEmpty() ? status : StatusData.create(status.getStatusCode(), "");
            }

            @Override
            public Attributes getAttributes() {
                AttributesBuilder kept = Attributes.builder();
                super.getAttributes().forEach((key, value) -> {
                    if (!URL_ATTRIBUTES.contains(key.getKey())) {
                        put(kept, key, value);
                    }
                });
                return kept.build();
            }
        };
    }

    private static EventData exceptionClassOnly(EventData event) {
        Attributes type = Attributes.empty();
        String name = event.getAttributes().get(EXCEPTION_TYPE);
        if (name != null) {
            type = Attributes.of(EXCEPTION_TYPE, name);
        }
        return EventData.create(event.getEpochNanos(), event.getName(), type);
    }

    @SuppressWarnings("unchecked")
    private static <T> void put(AttributesBuilder builder, AttributeKey<T> key, Object value) {
        builder.put(key, (T) value);
    }
}
