package pl.aiwcorpo.mcp.broker.system;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * GitLab: whoami is {@code GET /api/v4/user} with the login in {@code username} (C4.1), for personal access
 * tokens and OAuth access tokens alike. The OAuth side is the standard authorization code flow with PKCE
 * against {@code /oauth/authorize}, {@code /oauth/token} and {@code /oauth/revoke}; the client credentials go
 * in the request body. The client must not follow redirects: one to another host would carry a token or the
 * client secret there.
 */
public class GitLabAdapter implements SystemAdapter, OAuthProvider {

    private static final Pattern ERROR_CODE = Pattern.compile("^[a-z_]{1,40}$");

    private final URI baseUrl;
    private final Duration timeout;
    private final BrokerProperties.OAuth oauth;
    private final Supplier<SecretValue> clientSecret;
    private final UpstreamHttp http;

    public GitLabAdapter(URI baseUrl, Duration timeout, BrokerProperties.OAuth oauth, Supplier<SecretValue> clientSecret,
            HttpClient http, JsonMapper json) {
        this.baseUrl = baseUrl;
        this.timeout = timeout;
        this.oauth = oauth;
        this.clientSecret = clientSecret;
        this.http = new UpstreamHttp(http, json);
    }

    @Override
    public WhoamiResult whoami(CredentialScheme scheme, SecretValue secret) {
        if (!secret.isHeaderToken()) {
            return new WhoamiResult.Rejected();
        }
        HttpRequest request = HttpRequest.newBuilder(under("/api/v4/user"))
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
        JsonNode username = body.path("username");
        if (!username.isString() || username.stringValue().isBlank()) {
            throw new UpstreamUnavailableException("whoami answered without a user name");
        }
        JsonNode email = body.path("email");
        return new WhoamiResult.Identified(
                new BackendIdentity(username.stringValue(), email.isString() ? email.stringValue() : null));
    }

    @Override
    public URI authorizeUrl(String state, String codeChallenge, URI redirectUri, List<String> scopes) {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", oauth.clientId());
        query.put("response_type", "code");
        query.put("redirect_uri", redirectUri.toString());
        query.put("state", state);
        query.put("code_challenge", codeChallenge);
        query.put("code_challenge_method", "S256");
        if (!scopes.isEmpty()) {
            query.put("scope", String.join(" ", scopes));
        }
        URI authorize = oauth.authorizeUrl() != null ? oauth.authorizeUrl() : under("/oauth/authorize");
        String separator = authorize.getRawQuery() == null ? "?" : "&";
        return URI.create(authorize + separator + form(query));
    }

    @Override
    public TokenSet exchangeCode(SecretValue code, SecretValue codeVerifier, URI redirectUri) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("grant_type", "authorization_code");
        body.put("code", code.reveal());
        body.put("redirect_uri", redirectUri.toString());
        body.put("code_verifier", codeVerifier.reveal());
        return tokenRequest(body);
    }

    @Override
    public TokenSet refresh(SecretValue refreshToken) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("grant_type", "refresh_token");
        body.put("refresh_token", refreshToken.reveal());
        return tokenRequest(body);
    }

    @Override
    public void revoke(SecretValue token) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("token", token.reveal());
        HttpResponse<byte[]> response = http.send(post(endpoint(oauth.revokeUrl(), "/oauth/revoke"), body));
        if (response.statusCode() != 200) {
            throw new UpstreamUnavailableException("revoke answered HTTP " + response.statusCode());
        }
    }

    private TokenSet tokenRequest(Map<String, String> body) {
        HttpResponse<byte[]> response = http.send(post(endpoint(oauth.tokenUrl(), "/oauth/token"), body));
        int status = response.statusCode();
        if (status == 200) {
            return parseTokens(http.readJson(response, "token endpoint"));
        }
        if (status == 400 || status == 401) {
            JsonNode error = http.readJson(response, "token endpoint").path("error");
            if (error.isString() && "invalid_grant".equals(error.stringValue())) {
                throw new OAuthGrantRejectedException();
            }
            String code = error.isString() && ERROR_CODE.matcher(error.stringValue()).matches() ? error.stringValue() : "unknown";
            throw new UpstreamUnavailableException("token endpoint refused the request: " + code);
        }
        throw new UpstreamUnavailableException("token endpoint answered HTTP " + status);
    }

    private static TokenSet parseTokens(JsonNode body) {
        JsonNode access = body.path("access_token");
        JsonNode type = body.path("token_type");
        if (!access.isString() || access.stringValue().isEmpty()
                || !type.isString() || !"bearer".equalsIgnoreCase(type.stringValue())) {
            throw new UpstreamUnavailableException("token endpoint answered without a bearer access token");
        }
        SecretValue accessToken = SecretValue.of(access.stringValue());
        if (!accessToken.isHeaderToken()) {
            throw new UpstreamUnavailableException("token endpoint answered an access token that is not a header token");
        }
        JsonNode refresh = body.path("refresh_token");
        SecretValue refreshToken = refresh.isString() && !refresh.stringValue().isEmpty() ? SecretValue.of(refresh.stringValue()) : null;
        JsonNode expires = body.path("expires_in");
        Long expiresIn = expires.isIntegralNumber() && expires.asLong() > 0 ? expires.asLong() : null;
        return new TokenSet(accessToken, refreshToken, expiresIn);
    }

    private HttpRequest post(URI uri, Map<String, String> body) {
        Map<String, String> withClient = new LinkedHashMap<>(body);
        withClient.put("client_id", oauth.clientId());
        withClient.put("client_secret", clientSecret.get().reveal());
        return HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form(withClient)))
                .build();
    }

    private URI endpoint(URI configured, String defaultPath) {
        return configured != null ? configured : under(defaultPath);
    }

    private URI under(String path) {
        String base = baseUrl.toString();
        return URI.create(base.endsWith("/") ? base.substring(0, base.length() - 1) + path : base + path);
    }

    private static String form(Map<String, String> values) {
        StringBuilder out = new StringBuilder();
        values.forEach((name, value) -> {
            if (!out.isEmpty()) {
                out.append('&');
            }
            out.append(URLEncoder.encode(name, StandardCharsets.UTF_8)).append('=')
                    .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        });
        return out.toString();
    }
}
