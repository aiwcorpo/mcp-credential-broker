package pl.aiwcorpo.mcp.broker.support;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLContext;

import tools.jackson.databind.JsonNode;

/**
 * HTTPS client of the broker with one client certificate. Every response is recorded, so tests can check
 * that no response other than resolve carries a secret.
 */
public final class BrokerClient {

    public record Response(int status, String body, HttpResponse<String> raw) {

        public JsonNode json() {
            return Contracts.JSON.readTree(body);
        }

        public String header(String name) {
            return raw.headers().firstValue(name).orElse(null);
        }
    }

    private static final List<Response> RECORDED = Collections.synchronizedList(new ArrayList<>());

    private final HttpClient http;
    private final String baseUrl;

    public BrokerClient(SSLContext tls, int port) {
        this.http = HttpClient.newBuilder().sslContext(tls).connectTimeout(Duration.ofSeconds(5)).build();
        this.baseUrl = "https://localhost:" + port;
    }

    public static List<Response> recorded() {
        synchronized (RECORDED) {
            return List.copyOf(RECORDED);
        }
    }

    public Response send(String method, String path, String bearer, String requestId, String body) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(10))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        if (bearer != null) {
            request.header("Authorization", "Bearer " + bearer);
        }
        if (requestId != null) {
            request.header("X-Request-Id", requestId);
        }
        try {
            HttpResponse<String> raw = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
            Response response = new Response(raw.statusCode(), raw.body(), raw);
            RECORDED.add(response);
            return response;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
