package pl.aiwcorpo.mcp.broker.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import jakarta.validation.Validation;
import jakarta.validation.Validator;

class GatewayJwtTimingTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    private boolean valid(Duration refresh, Duration minInterval, Duration maxStale) {
        BrokerProperties.GatewayJwt config = new BrokerProperties.GatewayJwt("iss", "aud", null, null, null, false,
                Duration.ofSeconds(30), Duration.ofSeconds(60), refresh, minInterval, maxStale);
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
}
