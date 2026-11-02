package pl.aiwcorpo.mcp.broker.credential;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.broker.support.MutableClock;

@ExtendWith(OutputCaptureExtension.class)
class LostSecretSignalTest {

    private static final String LINE = "Connection metadata without a stored secret";

    private final MutableClock clock = new MutableClock(Instant.parse("2026-11-02T10:00:00Z"));
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();
    private final LostSecretSignal signal = new LostSecretSignal(clock, meters);

    private static int lines(CapturedOutput output) {
        return output.getOut().split(LINE, -1).length - 1;
    }

    @Test
    void everySightingIsCountedButTheLogRepeatsOncePerInterval(CapturedOutput output) {
        for (int minute = 0; minute < 14; minute++) {
            signal.seen("gitlab", LostSecretSignal.Place.REFRESH_SWEEP);
            clock.advance(Duration.ofMinutes(1));
        }
        assertThat(lines(output)).as("first sighting only").isEqualTo(1);
        assertThat(meters.counter(LostSecretSignal.METRIC, "system", "gitlab", "place", "refresh_sweep").count()).isEqualTo(14.0);

        clock.advance(Duration.ofMinutes(1));
        signal.seen("gitlab", LostSecretSignal.Place.REFRESH_SWEEP);
        assertThat(lines(output)).isEqualTo(2);
        assertThat(output.getOut()).contains("13 more since the last report");
    }

    @Test
    void anotherSystemOrPlaceIsReportedAtOnce(CapturedOutput output) {
        signal.seen("gitlab", LostSecretSignal.Place.REFRESH_SWEEP);
        signal.seen("gitlab", LostSecretSignal.Place.RESOLVE);
        signal.seen("jira", LostSecretSignal.Place.REFRESH_SWEEP);
        assertThat(lines(output)).isEqualTo(3);
    }

    @Test
    void theLineNamesNeitherUserNorSecret(CapturedOutput output) {
        signal.seen("gitlab", LostSecretSignal.Place.RESOLVE);
        assertThat(output.getOut()).contains("system gitlab").doesNotContain("sub").doesNotContain("mcp/connections");
    }
}
