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
 * same row more than once does not write a line each time. Neither carries the user or the secret path.
 * <p>
 * It also holds the brake of CC-205: {@link #mayMark} allows at most {@code maxMarks} state changes per {@code window}.
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
    static final String BRAKE_METRIC = "broker.connection.secret_missing_brake";

    private final Map<String, Report> reports = new ConcurrentHashMap<>();
    private final int maxMarks;
    private final Duration window;
    private Instant windowStart;
    private int marks;
    private boolean alarmed;

    public LostSecretSignal(Clock clock, MeterRegistry meters) {
        this(clock, meters, 10, Duration.ofMinutes(10));
    }

    public LostSecretSignal(Clock clock, MeterRegistry meters, int maxMarks, Duration window) {
        this.clock = clock;
        this.meters = meters;
        this.maxMarks = maxMarks;
        this.window = window;
    }

    /**
     * Whether one more connection may be put in state error. Over the limit nothing changes for the caller, who still
     * answers credential_required, but the row is left alone and the operator gets one alarm per window.
     */
    public synchronized boolean mayMark() {
        Instant now = clock.instant();
        if (windowStart == null || !now.isBefore(windowStart.plus(window))) {
            windowStart = now;
            marks = 0;
            alarmed = false;
        }
        if (marks < maxMarks) {
            marks++;
            return true;
        }
        meters.counter(BRAKE_METRIC).increment();
        if (!alarmed) {
            alarmed = true;
            log.error("More than {} connections without a stored secret within {}: marking them as failed is stopped until the"
                    + " window ends. Check the secret store (path prefix, mount, restored state) before users reconnect", maxMarks, window);
        }
        return false;
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
