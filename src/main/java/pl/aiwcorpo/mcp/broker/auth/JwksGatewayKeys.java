package pl.aiwcorpo.mcp.broker.auth;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;

/**
 * Gateway JWKS (C2) from its internal endpoint or from a file. Keys are refreshed periodically and on an
 * unknown kid (rotation publishes the new key ahead of use), but not more often than the minimum interval,
 * so a flood of tokens with random kids cannot turn into a flood of JWKS requests. A failed refresh keeps
 * the keys already loaded.
 */
public class JwksGatewayKeys implements GatewayKeys {

    private static final Logger log = LoggerFactory.getLogger(JwksGatewayKeys.class);

    private final Callable<String> source;
    private final String description;
    private final Clock clock;
    private final Duration refresh;
    private final Duration minRefreshInterval;

    private volatile Map<String, ECKey> keys = Map.of();
    private volatile Instant loadedAt = Instant.EPOCH;
    private volatile Instant attemptedAt = Instant.EPOCH;

    JwksGatewayKeys(Callable<String> source, String description, Clock clock, Duration refresh, Duration minRefreshInterval) {
        this.source = source;
        this.description = description;
        this.clock = clock;
        this.refresh = refresh;
        this.minRefreshInterval = minRefreshInterval;
    }

    public static JwksGatewayKeys fromFile(Path file, Clock clock) {
        return new JwksGatewayKeys(() -> Files.readString(file, StandardCharsets.UTF_8), file.toString(), clock,
                Duration.ofDays(3650), Duration.ofSeconds(10));
    }

    public static JwksGatewayKeys fromUri(URI uri, HttpClient http, Duration timeout, Clock clock, Duration refresh,
            Duration minRefreshInterval) {
        Callable<String> fetch = () -> {
            HttpRequest request = HttpRequest.newBuilder(uri).timeout(timeout).header("Accept", "application/json").GET().build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IOException("HTTP " + response.statusCode());
            }
            return response.body();
        };
        return new JwksGatewayKeys(fetch, uri.toString(), clock, refresh, minRefreshInterval);
    }

    @Override
    public Optional<ECKey> find(String kid) {
        Instant now = clock.instant();
        if (now.isAfter(loadedAt.plus(refresh))) {
            reload(now);
        }
        ECKey key = keys.get(kid);
        if (key == null) {
            reload(now);
            key = keys.get(kid);
        }
        return Optional.ofNullable(key);
    }

    private synchronized void reload(Instant now) {
        if (now.isBefore(attemptedAt.plus(minRefreshInterval))) {
            return;
        }
        attemptedAt = now;
        try {
            JWKSet set = JWKSet.parse(source.call());
            keys = set.getKeys().stream()
                    .filter(JwksGatewayKeys::usableSigningKey)
                    .map(JWK::toECKey)
                    .collect(Collectors.toUnmodifiableMap(JWK::getKeyID, k -> k, (a, b) -> a));
            loadedAt = now;
            log.info("Loaded {} gateway JWT keys from {}", keys.size(), description);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.warn("Gateway JWKS from {} not loaded ({}); keeping {} known keys", description,
                    e.getClass().getSimpleName(), keys.size());
        }
    }

    private static boolean usableSigningKey(JWK jwk) {
        return jwk instanceof ECKey ec
                && Curve.P_256.equals(ec.getCurve())
                && jwk.getKeyID() != null
                && !jwk.isPrivate()
                && (jwk.getKeyUse() == null || KeyUse.SIGNATURE.equals(jwk.getKeyUse()));
    }
}
