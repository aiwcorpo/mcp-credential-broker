package pl.aiwcorpo.mcp.broker.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Test;

class PurgeMarkerTtlTest {

    @Test
    void aMarkerShorterThanTheFlowsIsRefusedAtStart() {
        assertThatThrownBy(() -> BrokerConfiguration.requireMarkerCoversFlows(Duration.ofMinutes(5), Duration.ofMinutes(10)))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("purge-marker-ttl");
        assertThatCode(() -> BrokerConfiguration.requireMarkerCoversFlows(Duration.ofMinutes(10), Duration.ofMinutes(10)))
                .doesNotThrowAnyException();
    }
}
