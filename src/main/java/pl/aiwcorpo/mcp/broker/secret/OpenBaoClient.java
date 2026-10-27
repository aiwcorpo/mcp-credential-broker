package pl.aiwcorpo.mcp.broker.secret;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Minimal OpenBao (Vault-compatible) HTTP client: AppRole login, KV v2 and Transit. Response bodies are
 * never logged or put into exceptions, because Transit decrypt and KV read responses carry secret material.
 */
public class OpenBaoClient {

    private static final Logger log = LoggerFactory.getLogger(OpenBaoClient.class);

    /** Renew the token when this fraction of its lease is used, so calls never race its expiry. */
    private static final double RENEW_AT_LEASE_FRACTION = 0.75;

    /** A renewal granting less than this means token_max_ttl is close; a fresh login is due. */
    private static final long MIN_USEFUL_LEASE_SECONDS = 60;

    /** After a failed renewal and login, how long the still valid token is used before trying again. */
    private static final long RETRY_SECONDS = 10;

    private final BrokerProperties.OpenBao config;
    private final HttpClient http;
    private final JsonMapper json;
    private final Clock clock;

    private String token;
    private Instant tokenRenewAt = Instant.EPOCH;
    private Instant tokenExpiresAt = Instant.EPOCH;

    public OpenBaoClient(BrokerProperties.OpenBao config, HttpClient http, JsonMapper json, Clock clock) {
        this.config = config;
        this.http = http;
        this.json = json;
        this.clock = clock;
    }

    public record Response(int status, JsonNode body) {
    }

    public JsonNode read(String path) {
        Response response = call("GET", path, null);
        if (response.status() == 404) {
            return null;
        }
        requireOk(response, "read");
        return response.body();
    }

    public JsonNode write(String path, ObjectNode body) {
        Response response = call("POST", path, body);
        requireOk(response, "write");
        return response.body();
    }

    public void delete(String path) {
        Response response = call("DELETE", path, null);
        if (response.status() != 404) {
            requireOk(response, "delete");
        }
    }

    public ObjectNode object() {
        return json.createObjectNode();
    }

    private Response call(String method, String path, ObjectNode body) {
        Response response = send(method, path, body, currentToken());
        if (response.status() == 403) {
            // An expired or revoked token answers 403; one fresh login decides whether it is a real denial.
            invalidateToken();
            response = send(method, path, body, currentToken());
        }
        return response;
    }

    private static void requireOk(Response response, String operation) {
        if (response.status() < 200 || response.status() > 299) {
            throw new SecretStoreUnavailableException("secret store " + operation + " failed with HTTP " + response.status());
        }
    }

    /**
     * Token lifecycle: renew-self at 75% of the lease while token_max_ttl allows; near max TTL (or when
     * renewal fails) log in with AppRole again. If that login fails too (e.g. an expired secret_id), the
     * current token is kept until it really expires, so an AppRole problem degrades to a warning for the
     * remaining token lifetime instead of an immediate outage.
     */
    private synchronized String currentToken() {
        Instant now = clock.instant();
        if (token != null && now.isBefore(tokenRenewAt)) {
            return token;
        }
        if (token != null && now.isBefore(tokenExpiresAt)) {
            if (renewSelf(now)) {
                return token;
            }
            try {
                login(now);
            } catch (SecretStoreUnavailableException e) {
                log.warn("Secret store login failed ({}); using the current token until {}", e.getMessage(), tokenExpiresAt);
                tokenRenewAt = now.plusSeconds(RETRY_SECONDS);
            }
            return token;
        }
        login(now);
        return token;
    }

    private synchronized void invalidateToken() {
        token = null;
    }

    private boolean renewSelf(Instant now) {
        Response response = send("POST", "auth/token/renew-self", json.createObjectNode(), token);
        long lease = response.body().path("auth").path("lease_duration").asLong(0);
        if (response.status() != 200 || lease < MIN_USEFUL_LEASE_SECONDS) {
            return false;
        }
        tokenExpiresAt = now.plusSeconds(lease);
        tokenRenewAt = now.plusSeconds((long) (lease * RENEW_AT_LEASE_FRACTION));
        return true;
    }

    private void login(Instant now) {
        ObjectNode body = json.createObjectNode()
                .put("role_id", config.roleId())
                .put("secret_id", config.secretId());
        Response response = send("POST", "auth/approle/login", body, null);
        if (response.status() != 200) {
            throw new SecretStoreUnavailableException("secret store login failed with HTTP " + response.status());
        }
        JsonNode auth = response.body().path("auth");
        JsonNode clientToken = auth.path("client_token");
        if (!clientToken.isString() || clientToken.stringValue().isEmpty()) {
            throw new SecretStoreUnavailableException("secret store login returned no token");
        }
        long lease = Math.max(auth.path("lease_duration").asLong(0), 1);
        token = clientToken.stringValue();
        tokenExpiresAt = now.plusSeconds(lease);
        tokenRenewAt = now.plusSeconds((long) (lease * RENEW_AT_LEASE_FRACTION));
        log.info("Logged in to the secret store with AppRole, token lease {} s", lease);
    }

    private Response send(String method, String path, ObjectNode body, String vaultToken) {
        URI uri = config.address().resolve("/v1/" + path);
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .timeout(config.timeout())
                .header("Accept", "application/json");
        if (vaultToken != null) {
            request.header("X-Vault-Token", vaultToken);
        }
        if (body != null) {
            request.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofByteArray(json.writeValueAsBytes(body)));
        } else {
            request.method(method, HttpRequest.BodyPublishers.noBody());
        }
        try {
            HttpResponse<byte[]> response = http.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
            byte[] raw = response.body();
            JsonNode parsed = raw == null || raw.length == 0 ? json.createObjectNode() : json.readTree(raw);
            return new Response(response.statusCode(), parsed);
        } catch (IOException | JacksonException e) {
            throw new SecretStoreUnavailableException("secret store unreachable: " + e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SecretStoreUnavailableException("interrupted while calling the secret store");
        }
    }
}
