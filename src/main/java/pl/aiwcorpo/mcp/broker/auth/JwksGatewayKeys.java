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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;

/**
 * Gateway JWKS (C2) from its internal endpoint or from a file.
 * <ul>
 * <li>Refreshed periodically and on an unknown kid (rotation publishes the new key ahead of use), but not
 * more often than the minimum interval, so tokens with random kids cannot flood the JWKS endpoint.</li>
 * <li>A failed refresh keeps the loaded keys only up to {@code maxStale}; after that lookups fail with
 * {@link KeySourceUnavailableException}, so a key the gateway has retired stops working even while the
 * endpoint is down.</li>
 * <li>The first load and any lookup that finds the keys older than {@code maxStale} wait for the refresh in
 * progress (at most the lock wait, then the lookup fails); while the keys are within {@code maxStale}, one
 * thread refreshes and the others keep using the current keys.</li>
 * </ul>
 */
public class JwksGatewayKeys implements GatewayKeys {

    private static final Logger log = LoggerFactory.getLogger(JwksGatewayKeys.class);

    private final Callable<String> source;
    private final String description;
    private final Clock clock;
    private final Duration refresh;
    private final Duration minRefreshInterval;
    private final Duration maxStale;
    private final Duration lockWait;
    private final ReentrantLock refreshLock = new ReentrantLock();

    private volatile Map<String, ECKey> keys = Map.of();
    private volatile Instant loadedAt;
    private volatile Instant attemptedAt = Instant.EPOCH;

    JwksGatewayKeys(Callable<String> source, String description, Clock clock, Duration refresh, Duration minRefreshInterval,
            Duration maxStale) {
        this(source, description, clock, refresh, minRefreshInterval, maxStale, Duration.ofSeconds(10));
    }

    JwksGatewayKeys(Callable<String> source, String description, Clock clock, Duration refresh, Duration minRefreshInterval,
            Duration maxStale, Duration lockWait) {
        this.lockWait = lockWait;
        this.source = source;
        this.description = description;
        this.clock = clock;
        this.refresh = refresh;
        this.minRefreshInterval = minRefreshInterval;
        this.maxStale = maxStale;
    }

    public static JwksGatewayKeys fromFile(Path file, Clock clock) {
        Duration forever = Duration.ofDays(3650);
        return new JwksGatewayKeys(() -> Files.readString(file, StandardCharsets.UTF_8), file.toString(), clock,
                forever, Duration.ofSeconds(10), forever, Duration.ofSeconds(10));
    }

    public static JwksGatewayKeys fromUri(URI uri, HttpClient http, Duration timeout, Clock clock, Duration refresh,
            Duration minRefreshInterval, Duration maxStale) {
        Callable<String> fetch = () -> {
            HttpRequest request = HttpRequest.newBuilder(uri).timeout(timeout).header("Accept", "application/json").GET().build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IOException("HTTP " + response.statusCode());
            }
            return response.body();
        };
        // A waiter outlasts one fetch (bounded by the request timeout) but not a second one.
        return new JwksGatewayKeys(fetch, uri.toString(), clock, refresh, minRefreshInterval, maxStale,
                timeout.plusSeconds(1));
    }

    @Override
    public Optional<ECKey> find(String kid) {
        Instant now = clock.instant();
        if (loadedAt == null || now.isAfter(loadedAt.plus(refresh))) {
            reload(now);
        }
        ECKey key = keys.get(kid);
        if (key == null) {
            reload(now);
            key = keys.get(kid);
        }
        Instant loaded = loadedAt;
        if (loaded == null || clock.instant().isAfter(loaded.plus(maxStale))) {
            throw new KeySourceUnavailableException("gateway JWKS not loaded or older than " + maxStale);
        }
        return Optional.ofNullable(key);
    }

    private void reload(Instant requestedAt) {
        Instant loaded = loadedAt;
        boolean mustWait = loaded == null || requestedAt.isAfter(loaded.plus(maxStale));
        Instant now = requestedAt;
        try {
            if (mustWait) {
                if (!refreshLock.tryLock(lockWait.toMillis(), TimeUnit.MILLISECONDS)) {
                    log.warn("Gateway JWKS from {} still refreshing after {}", description, lockWait);
                    return;
                }
                // The refresh we waited for has already moved attemptedAt; judge the interval at the current time.
                now = clock.instant();
            } else if (!refreshLock.tryLock()) {
                return;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        }
        try {
            if (mustWait && loadedAt != loaded) {
                return;
            }
            if (now.isBefore(attemptedAt.plus(minRefreshInterval))) {
                return;
            }
            attemptedAt = now;
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
        } finally {
            refreshLock.unlock();
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
