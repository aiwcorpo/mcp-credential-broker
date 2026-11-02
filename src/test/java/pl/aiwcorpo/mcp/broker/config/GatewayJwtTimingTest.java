package pl.aiwcorpo.mcp.broker.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import jakarta.validation.Validation;
import jakarta.validation.Validator;

class GatewayJwtTimingTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    private boolean valid(Duration refresh, Duration minInterval, Duration maxStale) {
        return valid(refresh, minInterval, maxStale, Duration.ofSeconds(5));
    }

    private boolean valid(Duration refresh, Duration minInterval, Duration maxStale, Duration fetchTimeout) {
        BrokerProperties.GatewayJwt config = new BrokerProperties.GatewayJwt("iss", "aud", null, null, null, false,
                Duration.ofSeconds(30), Duration.ofSeconds(60), refresh, minInterval, maxStale, fetchTimeout);
        return validator.validate(config).isEmpty();
    }

    @Test
    void defaultsAreAccepted() {
        assertThat(valid(Duration.ofMinutes(5), Duration.ofSeconds(10), Duration.ofHours(1))).isTrue();
    }

    @Test
    void refreshLongerThanMaxStaleIsRejected() {
        assertThat(valid(Duration.ofHours(2), Duration.ofSeconds(10), Duration.ofHours(1))).isFalse();
    }

    @Test
    void subSecondMinimumIntervalAndNonPositiveRefreshAreRejected() {
        assertThat(valid(Duration.ofMinutes(5), Duration.ZERO, Duration.ofHours(1))).isFalse();
        assertThat(valid(Duration.ZERO, Duration.ofSeconds(10), Duration.ofHours(1))).isFalse();
    }

    @Test
    void minimumIntervalLongerThanRefreshIsRejected() {
        assertThat(valid(Duration.ofSeconds(30), Duration.ofSeconds(30), Duration.ofHours(1))).isTrue();
        assertThat(valid(Duration.ofSeconds(30), Duration.ofSeconds(31), Duration.ofHours(1))).isFalse();
    }

    @Test
    void fetchTimeoutMustBePositiveAndFitInTheMinimumInterval() {
        assertThat(valid(Duration.ofMinutes(5), Duration.ofSeconds(10), Duration.ofHours(1), Duration.ofSeconds(9))).isTrue();
        assertThat(valid(Duration.ofMinutes(5), Duration.ofSeconds(10), Duration.ofHours(1), Duration.ofSeconds(10))).isFalse();
        assertThat(valid(Duration.ofMinutes(5), Duration.ofSeconds(10), Duration.ofHours(1), Duration.ZERO)).isFalse();
    }

    @Test
    void refreshEqualToMaxStaleIsAcceptedAndMinimumIntervalOfOneSecondIsTheFloor() {
        assertThat(valid(Duration.ofHours(1), Duration.ofSeconds(10), Duration.ofHours(1))).isTrue();
        assertThat(valid(Duration.ofMinutes(5), Duration.ofSeconds(1), Duration.ofHours(1), Duration.ofMillis(500))).isTrue();
        assertThat(valid(Duration.ofMinutes(5), Duration.ofMillis(999), Duration.ofHours(1), Duration.ofMillis(500))).isFalse();
    }
}
