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

    @Test
    void theStatusSaysWhatIsStoredAndNothingOfTheKey() {
        String system = "sys-" + UUID.randomUUID();
        assertThat(keys.status(system)).isEqualTo(ServiceAccountKeys.Status.MISSING);

        Instant expiry = clock.instant().plusSeconds(3600).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        ServiceAccountKeys.Status written = keys.write(system,
                new ServiceAccountKeys.Entry("test-only-key-0001", null, null, expiry, "a.admin"));
        assertThat(written.set()).isTrue();
        assertThat(written.kvVersion()).isEqualTo(1);
        assertThat(written.expiresAt()).isEqualTo(expiry);
        assertThat(written.expired()).isFalse();
        assertThat(written.updatedBy()).isEqualTo("a.admin");

        ServiceAccountKeys.Status read = keys.status(system);
        assertThat(read.kvVersion()).isEqualTo(1);
        assertThat(read.expiresAt()).isEqualTo(expiry);
        assertThat(read.updatedBy()).isEqualTo("a.admin");
        assertThat(read.updatedAt()).isNotNull().isCloseTo(Instant.now(), org.assertj.core.api.Assertions.within(60, java.time.temporal.ChronoUnit.SECONDS));
        assertThat(read.toString()).doesNotContain("test-only-key-0001");
        assertThat(keys.read(system, CredentialScheme.BEARER).value().reveal()).as("what resolve reads").isEqualTo("test-only-key-0001");
    }

    @Test
    void anEntryOfAnOperatorHasNoWriterAndAnExpiredOneIsMarked() {
        String system = "sys-" + UUID.randomUUID();
        put(system, "{\"value\":\"k\",\"expires_at\":\"" + clock.instant().minusSeconds(5) + "\"}");
        ServiceAccountKeys.Status status = keys.status(system);
        assertThat(status.set()).isTrue();
        assertThat(status.updatedBy()).isNull();
        assertThat(status.expired()).isTrue();

        put(system, "{\"value\":\"k\",\"expires_at\":\"tomorrow\"}");
        assertThat(keys.status(system).expiresAt()).as("a status never fails on a malformed field").isNull();
    }

    @Test
    void aWriteReplacesTheWholeEntryAndTheLastWriteWins() {
        String system = "sys-" + UUID.randomUUID();
        keys.write(system, new ServiceAccountKeys.Entry("first", null, null, clock.instant().plusSeconds(600), "a.admin"));
        ServiceAccountKeys.Status second = keys.write(system, new ServiceAccountKeys.Entry(null, "svc-mcp", "p4ss", null, "b.admin"));

        assertThat(second.kvVersion()).isEqualTo(2);
        ServiceAccountKeys.Status read = keys.status(system);
        assertThat(read.expiresAt()).as("the old expires_at is not merged in").isNull();
        assertThat(read.updatedBy()).isEqualTo("b.admin");
        assertThat(new String(Base64.getDecoder().decode(keys.read(system, CredentialScheme.BASIC).value().reveal()), StandardCharsets.UTF_8))
                .isEqualTo("svc-mcp:p4ss");
        assertThatThrownBy(() -> keys.read(system, CredentialScheme.BEARER)).as("no value field is left over")
                .isInstanceOf(SecretStoreUnavailableException.class);
    }

    @Test
    void removeDeletesEveryVersionAndReportsTheCurrentOne() {
        String system = "sys-" + UUID.randomUUID();
        keys.write(system, new ServiceAccountKeys.Entry("one", null, null, null, null));
        keys.write(system, new ServiceAccountKeys.Entry("two", null, null, null, null));

        assertThat(keys.remove(system)).isEqualTo(2);

        assertThat(keys.status(system).set()).isFalse();
        assertThat(env.bao("GET", "secret/metadata/mcp/service-accounts/" + system, null).statusCode()).as("no version is recoverable").isEqualTo(404);
        assertThat(keys.remove(system)).as("nothing left is not an error").isNull();
    }

    @Test
    void aSoftDeletedCurrentVersionStillCountsAsAnEntryAndRemoveDropsTheHistory() {
        String system = "sys-" + UUID.randomUUID();
        keys.write(system, new ServiceAccountKeys.Entry("one", null, null, null, null));
        keys.write(system, new ServiceAccountKeys.Entry("two", null, null, null, null));
        assertThat(env.bao("DELETE", "secret/data/mcp/service-accounts/" + system, null).statusCode()).isEqualTo(204);

        assertThat(keys.status(system).set()).as("nothing is readable").isFalse();
        assertThat(keys.exists(system)).as("but the entry is there").isTrue();
        assertThat(keys.remove(system)).isNull();
        assertThat(env.bao("GET", "secret/metadata/mcp/service-accounts/" + system, null).statusCode()).as("the older version went too").isEqualTo(404);
        assertThat(keys.exists(system)).isFalse();
    }

    @Test
    void aDestroyedVersionIsGoneAndTheCurrentOneStays() {
        String system = "sys-" + UUID.randomUUID();
        keys.write(system, new ServiceAccountKeys.Entry("one", null, null, null, null));
        keys.write(system, new ServiceAccountKeys.Entry("two", null, null, null, null));

        keys.destroy(system, 1);
        keys.destroy(system, 1);

        assertThat(env.bao("GET", "secret/data/mcp/service-accounts/" + system + "?version=1", null).statusCode()).isEqualTo(404);
        assertThat(keys.read(system, CredentialScheme.BEARER).value().reveal()).isEqualTo("two");
    }

    private static void put(String system, String data) {
        assertThat(env.bao("POST", "secret/data/mcp/service-accounts/" + system, "{\"data\":" + data + "}").statusCode()).isEqualTo(200);
    }
}
