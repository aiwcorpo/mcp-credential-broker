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

/** The OAuth client secret from the real OpenBao of the test environment, with the broker's own AppRole and policy. */
class OAuthClientSecretsTest {

    private static final TestEnvironment env = TestEnvironment.get();

    private final MutableClock clock = new MutableClock(Instant.parse("2026-10-28T12:00:00Z"));
    private final OAuthClientSecrets secrets = new OAuthClientSecrets(
            new OpenBaoClient(new BrokerProperties.OpenBao(URI.create(env.openBaoUrl()), TestEnvironment.BAO_ROLE_ID,
                    TestEnvironment.BAO_SECRET_ID, "secret", "mcp/connections", "mcp/oauth-clients", "mcp/service-accounts", "transit",
                    "mcp-credential-broker", Duration.ofSeconds(5)), HttpClient.newHttpClient(), JsonMapper.builder().build(), clock),
            "secret", "mcp/oauth-clients", clock);

    @Test
    void aRotationIsPickedUpWhenTheRevisionOfTheSystemChangesOrTheCacheExpires() {
        String system = "sys-" + UUID.randomUUID();
        put(system, "first-value");
        assertThat(secrets.clientSecret(system, "rev-1").reveal()).isEqualTo("first-value");

        put(system, "second-value");
        assertThat(secrets.clientSecret(system, "rev-1").reveal()).as("cached").isEqualTo("first-value");
        assertThat(secrets.clientSecret(system, "rev-2").reveal()).as("another instance wrote: the etag moved").isEqualTo("second-value");

        put(system, "third-value");
        clock.advance(Duration.ofMinutes(6));
        assertThat(secrets.clientSecret(system, "rev-2").reveal()).isEqualTo("third-value");
    }

    @Test
    void withoutAStoredSecretThereIsNone() {
        String other = "sys-" + UUID.randomUUID();
        assertThatThrownBy(() -> secrets.clientSecret(other, "rev-1")).isInstanceOf(SecretStoreUnavailableException.class);
        assertThat(secrets.exists(other)).isFalse();
    }

    @Test
    void writeThenDeleteRemovesEveryVersion() {
        String system = "sys-" + UUID.randomUUID();
        secrets.write(system, SecretValue.of("one"));
        secrets.write(system, SecretValue.of("two"));
        assertThat(secrets.exists(system)).isTrue();
        assertThat(secrets.clientSecret(system, "rev-1").reveal()).isEqualTo("two");

        secrets.delete(system);

        assertThat(secrets.exists(system)).isFalse();
        assertThat(env.bao("GET", "secret/metadata/mcp/oauth-clients/" + system, null).statusCode()).isEqualTo(404);
        assertThatThrownBy(() -> secrets.clientSecret(system, "rev-1")).isInstanceOf(SecretStoreUnavailableException.class);
        secrets.delete(system);
    }

    private static void put(String system, String value) {
        var response = env.bao("POST", "secret/data/mcp/oauth-clients/" + system,
                "{\"data\":{\"client_id\":\"mcp-broker\",\"client_secret\":\"" + value + "\"}}");
        assertThat(response.statusCode()).isLessThan(300);
    }
}
