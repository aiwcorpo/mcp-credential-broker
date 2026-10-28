package pl.aiwcorpo.mcp.broker.system;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Calls to a target system: transport failures, bodies that are not JSON, bodies over {@link #MAX_BODY_BYTES} and
 * responses that do not complete within the request timeout (headers and body together) become
 * {@link UpstreamUnavailableException}. The JDK's per-request timeout stops at the response headers, so a
 * provider trickling the body would otherwise hold a thread, and with it the refresh lock, indefinitely.
 */
final class UpstreamHttp {

    static final int MAX_BODY_BYTES = 64 * 1024;
    private static final Duration DEFAULT_DEADLINE = Duration.ofSeconds(10);

    private final HttpClient http;
    private final JsonMapper json;

    UpstreamHttp(HttpClient http, JsonMapper json) {
        if (http.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("client for target systems must not follow redirects");
        }
        this.http = http;
        this.json = json;
    }

    HttpResponse<byte[]> send(HttpRequest request) {
        Duration deadline = request.timeout().orElse(DEFAULT_DEADLINE);
        CompletableFuture<HttpResponse<byte[]>> call = http.sendAsync(request, info -> new LimitedBody());
        try {
            return call.get(deadline.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            call.cancel(true);
            throw new UpstreamUnavailableException("target system did not answer in time");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof BodyTooLargeException) {
                throw new UpstreamUnavailableException("target system answered a body over " + MAX_BODY_BYTES + " bytes");
            }
            throw new UpstreamUnavailableException("target system unreachable: " + cause.getClass().getSimpleName());
        } catch (InterruptedException e) {
            call.cancel(true);
            Thread.currentThread().interrupt();
            throw new UpstreamUnavailableException("interrupted while calling the target system");
        }
    }

    JsonNode readJson(HttpResponse<byte[]> response, String what) {
        try {
            return json.readTree(response.body());
        } catch (JacksonException e) {
            throw new UpstreamUnavailableException(what + " answered a body that is not JSON");
        }
    }

    private static final class BodyTooLargeException extends IOException {
    }

    private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {

        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream received = new ByteArrayOutputStream();
        private Flow.Subscription subscription;

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                if (received.size() + buffer.remaining() > MAX_BODY_BYTES) {
                    subscription.cancel();
                    result.completeExceptionally(new BodyTooLargeException());
                    return;
                }
                byte[] chunk = new byte[buffer.remaining()];
                buffer.get(chunk);
                received.write(chunk, 0, chunk.length);
            }
        }

        @Override
        public void onError(Throwable error) {
            result.completeExceptionally(error);
        }

        @Override
        public void onComplete() {
            result.complete(received.toByteArray());
        }

        @Override
        public CompletableFuture<byte[]> getBody() {
            return result;
        }
    }
}
