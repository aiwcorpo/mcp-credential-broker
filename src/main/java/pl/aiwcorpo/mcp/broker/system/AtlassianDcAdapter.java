package pl.aiwcorpo.mcp.broker.system;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Jira and Confluence Data Center (D9). whoami is {@code GET /rest/api/2/myself} (C4.1); the user name is
 * {@code name}, the e-mail {@code emailAddress}. The HTTP client must not follow redirects: a redirect
 * to another host would carry the user's PAT there.
 */
public class AtlassianDcAdapter implements SystemAdapter {

    static final String WHOAMI_PATH = "/rest/api/2/myself";

    private final URI baseUrl;
    private final Duration timeout;
    private final HttpClient http;
    private final JsonMapper json;

    public AtlassianDcAdapter(URI baseUrl, Duration timeout, HttpClient http, JsonMapper json) {
        if (http.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("whoami client must not follow redirects");
        }
        this.baseUrl = baseUrl;
        this.timeout = timeout;
        this.http = http;
        this.json = json;
    }

    @Override
    public WhoamiResult whoami(CredentialScheme scheme, SecretValue secret) {
        if (!secret.isHeaderToken()) {
            return new WhoamiResult.Rejected();
        }
        HttpRequest request = HttpRequest.newBuilder(resolve(WHOAMI_PATH))
                .timeout(timeout)
                .header("Accept", "application/json")
                .header("Authorization", scheme.wire() + " " + secret.reveal())
                .GET()
                .build();
        HttpResponse<byte[]> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new UpstreamUnavailableException("whoami unreachable: " + e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new UpstreamUnavailableException("interrupted during whoami");
        }
        int status = response.statusCode();
        if (status == 401 || status == 403) {
            return new WhoamiResult.Rejected();
        }
        if (status != 200) {
            throw new UpstreamUnavailableException("whoami answered HTTP " + status);
        }
        JsonNode body;
        try {
            body = json.readTree(response.body());
        } catch (JacksonException e) {
            throw new UpstreamUnavailableException("whoami answered a body that is not JSON");
        }
        JsonNode name = body.path("name");
        if (!name.isString() || name.stringValue().isBlank()) {
            throw new UpstreamUnavailableException("whoami answered without a user name");
        }
        JsonNode email = body.path("emailAddress");
        return new WhoamiResult.Identified(
                new BackendIdentity(name.stringValue(), email.isString() ? email.stringValue() : null));
    }

    private URI resolve(String path) {
        String base = baseUrl.toString();
        return URI.create(base.endsWith("/") ? base.substring(0, base.length() - 1) + path : base + path);
    }
}
