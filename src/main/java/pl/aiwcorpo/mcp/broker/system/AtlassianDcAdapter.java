package pl.aiwcorpo.mcp.broker.system;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
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

    private final Product product;

    private final URI baseUrl;
    private final Duration timeout;
    private final UpstreamHttp http;

    public AtlassianDcAdapter(Product product, URI baseUrl, Duration timeout, HttpClient http, JsonMapper json) {
        this.product = product;
        this.baseUrl = baseUrl;
        this.timeout = timeout;
        this.http = new UpstreamHttp(http, json);
    }

    @Override
    public WhoamiResult whoami(CredentialScheme scheme, SecretValue secret) {
        if (!secret.isHeaderToken()) {
            return new WhoamiResult.Rejected();
        }
        HttpRequest request = HttpRequest.newBuilder(resolve(product.whoamiPath))
                .timeout(timeout)
                .header("Accept", "application/json")
                .header("Authorization", scheme.wire() + " " + secret.reveal())
                .GET()
                .build();
        HttpResponse<byte[]> response = http.send(request);
        int status = response.statusCode();
        if (status == 401 || status == 403) {
            return new WhoamiResult.Rejected();
        }
        if (status != 200) {
            throw new UpstreamUnavailableException("whoami answered HTTP " + status);
        }
        JsonNode body = http.readJson(response, "whoami");
        JsonNode name = body.path(product.loginField);
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
