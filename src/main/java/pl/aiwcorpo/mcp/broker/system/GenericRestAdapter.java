package pl.aiwcorpo.mcp.broker.system;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * A REST system the broker knows nothing specific about. As a service account it only hands out the platform's own key
 * and calls the system never. As a system with user secrets it checks a secret with the {@code whoami} the administrator
 * configured ({@code GET baseUrl+path}, the owner's name in {@code usernameField}), and without one takes the secret as it
 * is, with no owner. The client must not follow redirects: one to another host would carry the secret there.
 */
public class GenericRestAdapter implements ServiceAccountSource, SystemAdapter {

    private final String system;
    private final CredentialScheme scheme;
    private final ServiceAccountKeys keys;
    private final URI baseUrl;
    private final SystemDefinition.Whoami whoami;
    private final Duration timeout;
    private final UpstreamHttp http;

    public GenericRestAdapter(String system, CredentialScheme scheme, ServiceAccountKeys keys, URI baseUrl,
            SystemDefinition.Whoami whoami, Duration timeout, HttpClient http, JsonMapper json) {
        this.system = system;
        this.scheme = scheme;
        this.keys = keys;
        this.baseUrl = baseUrl;
        this.whoami = whoami;
        this.timeout = timeout;
        this.http = new UpstreamHttp(http, json);
    }

    public boolean hasWhoami() {
        return whoami != null;
    }

    @Override
    public ServiceAccountKeys.Key key() {
        return keys.read(system, scheme);
    }

    @Override
    public WhoamiResult whoami(CredentialScheme userScheme, SecretValue secret) {
        if (whoami == null) {
            return new WhoamiResult.Unverified();
        }
        if (!secret.isHeaderToken()) {
            return new WhoamiResult.Rejected();
        }
        String base = baseUrl.toString();
        HttpRequest request = HttpRequest.newBuilder(URI.create((base.endsWith("/") ? base.substring(0, base.length() - 1) : base)
                        + whoami.path()))
                .timeout(timeout)
                .header("Accept", "application/json")
                .header("Authorization", userScheme.wire() + " " + secret.reveal())
                .GET()
                .build();
        HttpResponse<byte[]> response = http.send(request);
        int status = response.statusCode();
        if (status == 401 || status == 403) {
            return new WhoamiResult.Rejected();
        }
        if (status < 200 || status > 299) {
            throw new UpstreamUnavailableException("whoami answered HTTP " + status);
        }
        JsonNode body = http.readJson(response, "whoami");
        JsonNode name = whoami.usernameField().startsWith("/") ? body.at(whoami.usernameField()) : body.path(whoami.usernameField());
        if (!name.isString() || !AuditLog.validBackendUser(name.stringValue())) {
            throw new UpstreamUnavailableException("whoami answered without a usable user name");
        }
        return new WhoamiResult.Identified(new BackendIdentity(name.stringValue(), null));
    }
}
