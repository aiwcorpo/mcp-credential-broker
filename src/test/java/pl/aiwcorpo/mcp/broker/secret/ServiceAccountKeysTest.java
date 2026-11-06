package pl.aiwcorpo.mcp.broker.secret;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.support.MutableClock;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import tools.jackson.databind.json.JsonMapper;

class ServiceAccountKeysTest {

    private static final TestEnvironment env = TestEnvironment.get();

    private final MutableClock clock = new MutableClock(Instant.now());
    private final ServiceAccountKeys keys = new ServiceAccountKeys(
            new OpenBaoClient(new BrokerProperties.OpenBao(URI.create(env.openBaoUrl()), TestEnvironment.BAO_ROLE_ID,
                    TestEnvironment.BAO_SECRET_ID, "secret", "mcp/connections", "mcp/oauth-clients", "mcp/system-clients", "mcp/service-accounts",
                    "transit", "mcp-credential-broker", Duration.ofSeconds(5)), HttpClient.newHttpClient(),
                    JsonMapper.builder().build(), Clock.systemUTC()),
            "secret", "mcp/service-accounts", clock);

    @Test
    void basicIsBuiltFromLoginAndPasswordAndOtherSchemesTakeTheValue() {
        String system = "sys-" + UUID.randomUUID();
        put(system, "{\"username\":\"svc-mcp\",\"password\":\"p4ss:word\"}");
        ServiceAccountKeys.Key basic = keys.read(system, CredentialScheme.BASIC);
        assertThat(new String(Base64.getDecoder().decode(basic.value().reveal()), StandardCharsets.UTF_8))
                .isEqualTo("svc-mcp:p4ss:word");
        assertThat(basic.expiresAt()).isNull();
        assertThatThrownBy(() -> keys.read(system, CredentialScheme.BEARER)).isInstanceOf(SecretStoreUnavailableException.class);

        put(system, "{\"value\":\"c3ZjOnNlY3JldA==\",\"expires_at\":\"" + clock.instant().plusSeconds(90) + "\"}");
        ServiceAccountKeys.Key precomputed = keys.read(system, CredentialScheme.BASIC);
        assertThat(precomputed.value().reveal()).isEqualTo("c3ZjOnNlY3JldA==");
        assertThat(precomputed.expiresAt()).isEqualTo(clock.instant().plusSeconds(90).truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
    }

    @Test
    void aBasicLoginWithAColonIsRefused() {
        String system = "sys-" + UUID.randomUUID();
        put(system, "{\"username\":\"svc:mcp\",\"password\":\"x\"}");
        assertThatThrownBy(() -> keys.read(system, CredentialScheme.BASIC)).isInstanceOf(SecretStoreUnavailableException.class);
    }

    @Test
    void aKeyThatExpiresIsRefusedFromItsExpiry() {
        String system = "sys-" + UUID.randomUUID();
        put(system, "{\"value\":\"k\",\"expires_at\":\"" + clock.instant().plusSeconds(30) + "\"}");
        assertThat(keys.read(system, CredentialScheme.BEARER).value().reveal()).isEqualTo("k");
        clock.advance(Duration.ofSeconds(31));
        assertThatThrownBy(() -> keys.read(system, CredentialScheme.BEARER)).isInstanceOf(SecretStoreUnavailableException.class);
    }

    private static void put(String system, String data) {
        assertThat(env.bao("POST", "secret/data/mcp/service-accounts/" + system, "{\"data\":" + data + "}").statusCode()).isEqualTo(200);
    }
}
