package pl.aiwcorpo.mcp.broker.system;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Calls to a target system: transport failures and bodies that are not JSON become {@link UpstreamUnavailableException}. */
final class UpstreamHttp {

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
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new UpstreamUnavailableException("target system unreachable: " + e.getClass().getSimpleName());
        } catch (InterruptedException e) {
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
}
