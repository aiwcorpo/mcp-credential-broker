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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
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
 * <li>The first load, a lookup that finds the keys older than {@code maxStale} and a lookup of an unknown kid
 * wait for the refresh in progress (at most the lock wait, then the lookup fails). An unknown kid while the
 * last refresh failed is also {@link KeySourceUnavailableException}, not an answer that the kid does not
 * exist. While the keys are within {@code maxStale} and the kid is known, one thread refreshes and the others
 * keep using the current keys.</li>
 * <li>Waiting parks a request thread, so at most {@code maxWaiters} lookups wait at once; the others fail at
 * once with the same {@link KeySourceUnavailableException}. Tokens with random kids against an endpoint that
 * hangs therefore cannot fill the request thread pool.</li>
 * <li>One fetch is bounded as a whole (connection, headers and body) and its body is capped, so the thread
 * holding the refresh lock cannot hang or grow memory without limit.</li>
 * </ul>
 */
public class JwksGatewayKeys implements GatewayKeys {

    private static final Logger log = LoggerFactory.getLogger(JwksGatewayKeys.class);

    static final int MAX_BODY_BYTES = 256 * 1024;
    static final int DEFAULT_MAX_WAITERS = 32;
    private static final Duration LOCK_WAIT_MARGIN = Duration.ofSeconds(1);

    private final Callable<String> source;
    private final String description;
    private final Clock clock;
    private final Duration refresh;
    private final Duration minRefreshInterval;
    private final Duration maxStale;
    private final Duration lockWait;
    private final ReentrantLock refreshLock = new ReentrantLock();
    private final Semaphore waitSlots;

    /** Keys and the time they were loaded travel together so a reader never sees one without the other. */
    private record Loaded(Map<String, ECKey> keys, Instant at) {
    }

    private record Refreshed(Loaded loaded, boolean gaveUp) {
    }

    private volatile Loaded loaded;
    private volatile boolean lastRefreshFailed;
    // Guarded by refreshLock.
    private Instant attemptedAt = Instant.EPOCH;

    JwksGatewayKeys(Callable<String> source, String description, Clock clock, Duration refresh, Duration minRefreshInterval,
            Duration maxStale) {
        this(source, description, clock, refresh, minRefreshInterval, maxStale, Duration.ofSeconds(10));
    }

    JwksGatewayKeys(Callable<String> source, String description, Clock clock, Duration refresh, Duration minRefreshInterval,
            Duration maxStale, Duration lockWait) {
        this(source, description, clock, refresh, minRefreshInterval, maxStale, lockWait, DEFAULT_MAX_WAITERS);
    }

    JwksGatewayKeys(Callable<String> source, String description, Clock clock, Duration refresh, Duration minRefreshInterval,
            Duration maxStale, Duration lockWait, int maxWaiters) {
        this.waitSlots = new Semaphore(maxWaiters);
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
        return new JwksGatewayKeys(() -> fetch(uri, http, timeout), uri.toString(), clock, refresh, minRefreshInterval,
                maxStale, lockWaitFor(timeout));
    }

    /** A waiter outlasts one fetch (hard-bounded by the timeout) but not a second one. */
    static Duration lockWaitFor(Duration fetchTimeout) {
        return fetchTimeout.plus(LOCK_WAIT_MARGIN);
    }

    Duration lockWait() {
        return lockWait;
    }

    boolean hasWaitingThreads() {
        return refreshLock.hasQueuedThreads();
    }

    /**
     * HttpRequest.timeout does not cover reading the body on every JDK (a server that sends headers and goes
     * silent kept send() blocked on JDK 25), so the whole exchange is bounded here and cancelled on expiry.
     */
    static String fetch(URI uri, HttpClient http, Duration timeout) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(uri).timeout(timeout).header("Accept", "application/json").GET().build();
        CompletableFuture<HttpResponse<byte[]>> pending = http.sendAsync(request,
                HttpResponse.BodyHandlers.limiting(HttpResponse.BodyHandlers.ofByteArray(), MAX_BODY_BYTES + 1L));
        try {
            HttpResponse<byte[]> response = pending.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (response.statusCode() != 200) {
                throw new IOException("HTTP " + response.statusCode());
            }
            if (response.body().length > MAX_BODY_BYTES) {
                throw new IOException("response larger than " + MAX_BODY_BYTES + " bytes");
            }
            return new String(response.body(), StandardCharsets.UTF_8);
        } catch (TimeoutException e) {
            throw new IOException("no complete response within " + timeout, e);
        } catch (ExecutionException e) {
            throw new IOException("fetch failed: " + e.getCause().getClass().getSimpleName(), e);
        } finally {
            pending.cancel(true);
        }
    }

    @Override
    public Optional<ECKey> find(String kid) {
        Instant now = clock.instant();
        Loaded seen = loaded;
        boolean stale = isStale(seen, now);
        ECKey key = stale ? null : seen.keys().get(kid);
        boolean gaveUp = false;
        if (stale || key == null || now.isAfter(seen.at().plus(refresh))) {
            // Stale keys read as no key at all, so both "too old" and "unknown kid" mean the answer depends on
            // the refresh and the lookup waits for it; a known kid on keys that are merely due does not.
            Refreshed result = refreshKeys(seen, key == null);
            seen = result.loaded();
            gaveUp = result.gaveUp();
        }
        // Judged at the time the lookup started, so a lookup that began inside maxStale is not failed by a refresh
        // that happens to be in progress when the boundary passes.
        if (isStale(seen, now)) {
            throw new KeySourceUnavailableException("gateway JWKS not loaded or older than " + maxStale);
        }
        key = seen.keys().get(kid);
        if (key == null && (gaveUp || lastRefreshFailed)) {
            throw new KeySourceUnavailableException("gateway JWKS cannot be refreshed, kid cannot be ruled out");
        }
        return Optional.ofNullable(key);
    }

    private boolean isStale(Loaded snapshot, Instant now) {
        return snapshot == null || now.isAfter(snapshot.at().plus(maxStale));
    }

    private Refreshed refreshKeys(Loaded seen, boolean wait) {
        try {
            if (wait) {
                if (!refreshLock.tryLock()) {
                    if (!waitSlots.tryAcquire()) {
                        return new Refreshed(loaded, true);
                    }
                    try {
                        if (!refreshLock.tryLock(lockWait.toMillis(), TimeUnit.MILLISECONDS)) {
                            log.warn("Gateway JWKS from {} still refreshing after {}", description, lockWait);
                            return new Refreshed(loaded, true);
                        }
                    } finally {
                        waitSlots.release();
                    }
                }
            } else if (!refreshLock.tryLock()) {
                return new Refreshed(loaded, false);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Refreshed(loaded, true);
        }
        try {
            if (loaded != seen) {
                return new Refreshed(loaded, false);
            }
            // After waiting, the interval is judged at the current time, not at the time the lookup started.
            Instant now = clock.instant();
            if (now.isBefore(attemptedAt.plus(minRefreshInterval))) {
                return new Refreshed(loaded, false);
            }
            attemptedAt = now;
            JWKSet set = JWKSet.parse(source.call());
            Map<String, ECKey> parsed = set.getKeys().stream()
                    .filter(JwksGatewayKeys::usableSigningKey)
                    .map(JWK::toECKey)
                    .collect(Collectors.toUnmodifiableMap(JWK::getKeyID, k -> k, (a, b) -> a));
            if (parsed.isEmpty()) {
                throw new IOException("no usable signing key in the response");
            }
            loaded = new Loaded(parsed, now);
            lastRefreshFailed = false;
            log.info("Loaded {} gateway JWT keys from {}", parsed.size(), description);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            lastRefreshFailed = true;
        } catch (Exception e) {
            lastRefreshFailed = true;
            Loaded known = loaded;
            log.warn("Gateway JWKS from {} not loaded ({}); keeping {} known keys", description,
                    e.getClass().getSimpleName(), known == null ? 0 : known.keys().size());
        } finally {
            refreshLock.unlock();
        }
        return new Refreshed(loaded, false);
    }

    private static boolean usableSigningKey(JWK jwk) {
        return jwk instanceof ECKey ec
                && Curve.P_256.equals(ec.getCurve())
                && jwk.getKeyID() != null
                && !jwk.isPrivate()
                && (jwk.getKeyUse() == null || KeyUse.SIGNATURE.equals(jwk.getKeyUse()));
    }
}
