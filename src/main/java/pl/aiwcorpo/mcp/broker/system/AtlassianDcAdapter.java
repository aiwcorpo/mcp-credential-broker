package pl.aiwcorpo.mcp.broker.system;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Jira and Confluence Data Center (D9). whoami differs per product (C4.1, CC-073): Jira answers
 * {@code GET /rest/api/2/myself} with the login in {@code name}, Confluence {@code GET /rest/api/user/current}
 * with the login in {@code username}. Confluence does not send an e-mail there. The HTTP client must not
 * follow redirects: a redirect to another host would carry the user's PAT there.
 */
public class AtlassianDcAdapter implements SystemAdapter {

    /** Which product the adapter talks to; decides the whoami path and the field holding the login. */
    public enum Product {
        JIRA("/rest/api/2/myself", "name"),
        CONFLUENCE("/rest/api/user/current", "username");

        private final String whoamiPath;
        private final String loginField;

        Product(String whoamiPath, String loginField) {
            this.whoamiPath = whoamiPath;
            this.loginField = loginField;
        }

        String whoamiPath() {
            return whoamiPath;
        }
    }

    /** Fixed product, or null when the adapter finds out which one answers on the base URL (the admin API names no product). */
    private final Product product;
    private volatile Product detected;

    private final URI baseUrl;
    private final Duration timeout;
    private final HttpClient http;
    private final JsonMapper json;

    public AtlassianDcAdapter(URI baseUrl, Duration timeout, HttpClient http, JsonMapper json) {
        this(null, baseUrl, timeout, http, json);
    }

    public AtlassianDcAdapter(Product product, URI baseUrl, Duration timeout, HttpClient http, JsonMapper json) {
        if (http.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("whoami client must not follow redirects");
        }
        this.product = product;
        this.baseUrl = baseUrl;
        this.timeout = timeout;
        this.http = http;
        this.json = json;
    }

    /**
     * Without a configured product, Jira's path is tried first and Confluence's when the host answers 404 there; the product
     * that answered is remembered. Each product answers 404 on the other's path.
     */
    @Override
    public WhoamiResult whoami(CredentialScheme scheme, SecretValue secret) {
        if (!secret.isHeaderToken()) {
            return new WhoamiResult.Rejected();
        }
        Product known = product != null ? product : detected;
        if (known != null) {
            return whoami(known, scheme, secret).orElseThrow(() -> new UpstreamUnavailableException("whoami answered HTTP 404"));
        }
        for (Product candidate : Product.values()) {
            Optional<WhoamiResult> result = whoami(candidate, scheme, secret);
            if (result.isPresent()) {
                detected = candidate;
                return result.get();
            }
        }
        throw new UpstreamUnavailableException("whoami answered HTTP 404");
    }

    /** Empty when the host does not know the path of this product (404). */
    private Optional<WhoamiResult> whoami(Product forProduct, CredentialScheme scheme, SecretValue secret) {
        HttpRequest request = HttpRequest.newBuilder(resolve(forProduct.whoamiPath))
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
        if (status == 404) {
            return Optional.empty();
        }
        if (status == 401 || status == 403) {
            return Optional.of(new WhoamiResult.Rejected());
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
        JsonNode name = body.path(forProduct.loginField);
        if (!name.isString() || name.stringValue().isBlank()) {
            throw new UpstreamUnavailableException("whoami answered without a user name");
        }
        JsonNode email = body.path("emailAddress");
        return Optional.of(new WhoamiResult.Identified(
                new BackendIdentity(name.stringValue(), email.isString() ? email.stringValue() : null)));
    }

    private URI resolve(String path) {
        String base = baseUrl.toString();
        return URI.create(base.endsWith("/") ? base.substring(0, base.length() - 1) + path : base + path);
    }
}
