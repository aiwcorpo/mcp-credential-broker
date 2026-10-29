package pl.aiwcorpo.mcp.broker.system;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.JWTParser;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * OpenSearch takes a token issued by the IdP for its own audience; the broker gets it by RFC 8693 token exchange
 * with the user's token (aud mcp-credential-broker) as the subject, so the IdP decides whether this user may use
 * the resource and the token carries the user's identity. The broker authenticates to the IdP as a confidential
 * client (client_secret_basic); its secret comes from OpenBao. Nothing is stored: every resolve exchanges again
 * and the gateway caches the result for at most {@code cacheTtlSeconds}.
 *
 * <p>Which IdP answers mean "this user is refused" and which mean "the broker is misconfigured" is a judgement,
 * because IdPs share error codes between the two (Keycloak says invalid_request for an audience the user cannot
 * get). The client errors in {@link #DENIED} are the user's; invalid_client and its relatives are the installation's
 * and are 503, as is everything unknown.
 */
public class OpenSearchAdapter implements TokenExchanger {

    private static final Logger log = LoggerFactory.getLogger(OpenSearchAdapter.class);
    private static final Pattern ERROR_CODE = Pattern.compile("^[a-z_]{1,40}$");
    private static final Set<String> DENIED = Set.of("access_denied", "invalid_grant", "invalid_target", "invalid_request",
            "invalid_scope", "invalid_token");

    private final BrokerProperties.TokenExchange exchange;
    private final Duration timeout;
    private final Supplier<SecretValue> clientSecret;
    private final UpstreamHttp http;
    private final Clock clock;

    public OpenSearchAdapter(BrokerProperties.TokenExchange exchange, Duration timeout, Supplier<SecretValue> clientSecret,
            HttpClient http, JsonMapper json, Clock clock) {
        this.exchange = exchange;
        this.timeout = timeout;
        this.clientSecret = clientSecret;
        this.http = new UpstreamHttp(http, json);
        this.clock = clock;
    }

    @Override
    public ExchangedToken exchange(SecretValue subjectToken) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        form.put("subject_token", subjectToken.reveal());
        form.put("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
        form.put("requested_token_type", "urn:ietf:params:oauth:token-type:access_token");
        form.put("audience", exchange.audience());
        if (!exchange.scopes().isEmpty()) {
            form.put("scope", String.join(" ", exchange.scopes()));
        }
        Instant sent = clock.instant();
        HttpResponse<byte[]> response = http.send(request(form));
        int status = response.statusCode();
        if (status == 200) {
            return parse(http.readJson(response, "token endpoint"), sent);
        }
        if (status >= 400 && status < 500) {
            String error = errorCode(response);
            if (DENIED.contains(error)) {
                log.info("IdP refused the token exchange for audience {}: {}", exchange.audience(), error);
                throw new ExchangeDeniedException();
            }
            throw new UpstreamUnavailableException("token endpoint refused the broker's request: " + error);
        }
        throw new UpstreamUnavailableException("token endpoint answered HTTP " + status);
    }

    private ExchangedToken parse(JsonNode body, Instant sent) {
        JsonNode access = body.path("access_token");
        if (!access.isString() || access.stringValue().isEmpty()) {
            throw new UpstreamUnavailableException("token endpoint answered without an access token");
        }
        SecretValue token = SecretValue.of(access.stringValue());
        if (!token.isHeaderToken()) {
            throw new UpstreamUnavailableException("token endpoint answered an access token that is not a header token");
        }
        JsonNode expiresIn = body.path("expires_in");
        Instant expiresAt = expiresIn.isIntegralNumber() && expiresIn.asLong() > 0
                ? sent.plusSeconds(expiresIn.asLong())
                : expiryClaim(access.stringValue());
        if (expiresAt == null || !expiresAt.isAfter(clock.instant())) {
            throw new UpstreamUnavailableException("token endpoint answered a token without a usable expiry");
        }
        return new ExchangedToken(token, expiresAt.truncatedTo(ChronoUnit.SECONDS));
    }

    /** Fallback when the IdP leaves out expires_in: the exp of the token it just issued (not a check of the token). */
    private static Instant expiryClaim(String jwt) {
        try {
            var exp = JWTParser.parse(jwt).getJWTClaimsSet().getExpirationTime();
            return exp == null ? null : exp.toInstant();
        } catch (ParseException e) {
            return null;
        }
    }

    private String errorCode(HttpResponse<byte[]> response) {
        try {
            JsonNode error = http.readJson(response, "token endpoint").path("error");
            return error.isString() && ERROR_CODE.matcher(error.stringValue()).matches() ? error.stringValue() : "unknown";
        } catch (UpstreamUnavailableException e) {
            return "unknown";
        }
    }

    private HttpRequest request(Map<String, String> form) {
        String credentials = urlEncode(exchange.clientId()) + ":" + urlEncode(clientSecret.get().reveal());
        return HttpRequest.newBuilder(exchange.tokenUrl())
                .timeout(timeout)
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)))
                .POST(HttpRequest.BodyPublishers.ofString(encode(form)))
                .build();
    }

    private static String encode(Map<String, String> values) {
        StringBuilder out = new StringBuilder();
        values.forEach((name, value) -> {
            if (!out.isEmpty()) {
                out.append('&');
            }
            out.append(urlEncode(name)).append('=').append(urlEncode(value));
        });
        return out.toString();
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
