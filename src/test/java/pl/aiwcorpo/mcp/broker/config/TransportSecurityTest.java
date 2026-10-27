package pl.aiwcorpo.mcp.broker.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;

import org.junit.jupiter.api.Test;

class TransportSecurityTest {

    @Test
    void plainHttpOnlyWithTheDevelopmentFlag() {
        assertThatCode(() -> BrokerConfiguration.requireTls(URI.create("https://openbao.internal:8200"), "p", false))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> BrokerConfiguration.requireTls(URI.create("http://openbao:8200"), "p", false))
                .isInstanceOf(IllegalStateException.class);
        assertThatCode(() -> BrokerConfiguration.requireTls(URI.create("http://openbao:8200"), "p", true))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> BrokerConfiguration.requireTls(URI.create("ftp://x"), "p", true))
                .isInstanceOf(IllegalStateException.class);
    }
}
