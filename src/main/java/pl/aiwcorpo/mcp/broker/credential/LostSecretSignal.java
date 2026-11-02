package pl.aiwcorpo.mcp.broker.credential;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * Tells the operator that a connection row exists whose secret is gone from the store (OpenBao data lost or
 * restored from an older state). The caller still gets credential_required; this is only the signal.
 * <p>
 * The counter is bumped on every sighting. The log line is written for the first sighting per system and
 * place, then at most once per interval with the number of sightings it stands for, so a sweep that meets the
 * same row every minute does not write a line every minute. Neither carries the user or the secret path.
 */
public class LostSecretSignal {

    static final Duration LOG_INTERVAL = Duration.ofMinutes(15);
    static final String METRIC = "broker.connection.secret_missing";

    private static final Logger log = LoggerFactory.getLogger(LostSecretSignal.class);

    /** Where the missing secret was noticed. */
    public enum Place { RESOLVE, REFRESH_SWEEP }

    private record Report(Instant at, long suppressed) {
    }

    private final Clock clock;
    private final MeterRegistry meters;
    private final Map<String, Report> reports = new ConcurrentHashMap<>();

    public LostSecretSignal(Clock clock, MeterRegistry meters) {
        this.clock = clock;
        this.meters = meters;
    }

    public void seen(String system, Place place) {
        meters.counter(METRIC, "system", system, "place", place.name().toLowerCase()).increment();
        Instant now = clock.instant();
        long[] repeated = {-1};
        reports.compute(system + "/" + place, (key, last) -> {
            if (last == null || !now.isBefore(last.at().plus(LOG_INTERVAL))) {
                repeated[0] = last == null ? 0 : last.suppressed();
                return new Report(now, 0);
            }
            return new Report(last.at(), last.suppressed() + 1);
        });
        if (repeated[0] >= 0) {
            log.warn("Connection metadata without a stored secret for system {} (noticed in {}, {} more since the last report)",
                    system, place.name().toLowerCase(), repeated[0]);
        }
    }
}
