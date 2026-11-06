package pl.aiwcorpo.mcp.broker.secret;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.support.MutableClock;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import tools.jackson.databind.json.JsonMapper;

/** The client secrets from the real OpenBao of the test environment, with the broker's own AppRole and policy. */
class OAuthClientSecretsTest {

    private static final TestEnvironment env = TestEnvironment.get();

    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-28T12:00:00Z"));
    private final OAuthClientSecrets secrets = new OAuthClientSecrets(
            new OpenBaoClient(new BrokerProperties.OpenBao(URI.create(env.openBaoUrl()), TestEnvironment.BAO_ROLE_ID,
                    TestEnvironment.BAO_SECRET_ID, "secret", "mcp/connections", "mcp/oauth-clients", "mcp/system-clients",
                    "mcp/service-accounts", "transit", "mcp-credential-broker", Duration.ofSeconds(5)), HttpClient.newHttpClient(),
                    JsonMapper.builder().build(), clock),
            "secret", "mcp/system-clients", "mcp/oauth-clients", clock);

    @Test
    void everyWriteIsANewVersionAndAReaderGetsExactlyTheVersionItAsksFor() {
        String system = "sys" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        assertThat(secrets.write(system, SecretValue.of("first-value"))).isEqualTo(1);
        assertThat(secrets.write(system, SecretValue.of("second-value"))).isEqualTo(2);

        assertThat(secrets.read(system, 1).reveal()).isEqualTo("first-value");
        assertThat(secrets.read(system, 2).reveal()).isEqualTo("second-value");
        assertThatThrownBy(() -> secrets.read(system, 3)).isInstanceOf(SecretStoreUnavailableException.class);
        assertThatThrownBy(() -> secrets.read(system, null)).isInstanceOf(SecretStoreUnavailableException.class);
    }

    @Test
    void aDestroyedVersionIsGoneAndTheOthersStay() {
        String system = "sys" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        secrets.write(system, SecretValue.of("one"));
        secrets.write(system, SecretValue.of("two"));

        secrets.destroy(system, 1);
        clock.advance(Duration.ofMinutes(6));

        assertThatThrownBy(() -> secrets.read(system, 1)).isInstanceOf(SecretStoreUnavailableException.class);
        assertThat(secrets.read(system, 2).reveal()).isEqualTo("two");
        secrets.destroy(system, 1);
        assertThat(env.bao("GET", "secret/data/mcp/system-clients/" + system + "?version=2", null).statusCode()).isEqualTo(200);
    }

    @Test
    void aSecretIsCachedPerVersionOnly() {
        String system = "sys" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        secrets.write(system, SecretValue.of("one"));
        assertThat(secrets.read(system, 1).reveal()).isEqualTo("one");
        env.bao("POST", "secret/destroy/mcp/system-clients/" + system, "{\"versions\":[1]}");
        assertThat(secrets.read(system, 1).reveal()).as("immutable, so cached for the window").isEqualTo("one");
        clock.advance(Duration.ofMinutes(6));
        assertThatThrownBy(() -> secrets.read(system, 1)).isInstanceOf(SecretStoreUnavailableException.class);
    }

    @Test
    void theOldPathOfOneDotXIsReadOnlyForTheImport() {
        String system = "sys" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        assertThat(secrets.readLegacy(system)).isEmpty();
        var stored = env.bao("POST", "secret/data/mcp/oauth-clients/" + system, "{\"data\":{\"client_secret\":\"from-1x\"}}");
        assertThat(stored.statusCode()).isLessThan(300);

        assertThat(secrets.readLegacy(system)).hasValueSatisfying(value -> assertThat(value.reveal()).isEqualTo("from-1x"));
        assertThatThrownBy(() -> secrets.read(system, 1)).as("not the path of the admin API").isInstanceOf(SecretStoreUnavailableException.class);
    }
}
