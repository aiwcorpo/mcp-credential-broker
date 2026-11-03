package pl.aiwcorpo.mcp.broker.system;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;
import tools.jackson.databind.json.JsonMapper;

/** CC-168: service-account is never mixed with the types of a user; such a configuration stops the start. */
class SystemRegistryTest {

    @Test
    void serviceAccountMixedWithUserTypesRefusesToStart() {
        assertRefused("generic-rest", List.of(CredentialType.SERVICE_ACCOUNT, CredentialType.USER_SECRET), CredentialType.SERVICE_ACCOUNT);
        assertRefused("atlassian-dc", List.of(CredentialType.USER_SECRET, CredentialType.SERVICE_ACCOUNT), CredentialType.USER_SECRET);
        assertRefused("generic-rest", List.of(CredentialType.SERVICE_ACCOUNT, CredentialType.TOKEN_EXCHANGE), CredentialType.SERVICE_ACCOUNT);
    }

    private static void assertRefused(String adapter, List<CredentialType> types, CredentialType defaultType) {
        BrokerProperties.SystemConfig config = new BrokerProperties.SystemConfig(URI.create("http://servicedesk.test"), adapter, types,
                defaultType, CredentialScheme.BEARER, List.of(), Duration.ofSeconds(1), null, null, null, null);
        assertThatThrownBy(() -> new SystemRegistry(Map.of("servicedesk", config), HttpClient.newHttpClient(),
                JsonMapper.builder().build(), mock(OAuthClientSecrets.class), mock(ServiceAccountKeys.class), Clock.systemUTC(),
                new SimpleMeterRegistry())).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aBasicUserSecretNeedsTheUserSecretType() {
        assertThatThrownBy(() -> new BrokerProperties.SystemConfig(URI.create("http://gitlab.test"), "gitlab",
                List.of(CredentialType.USER_OAUTH), CredentialType.USER_OAUTH, CredentialScheme.BEARER, List.of(),
                Duration.ofSeconds(1), null, null, CredentialScheme.BASIC, null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BrokerProperties.SystemConfig(URI.create("http://jira.test"), "atlassian-dc",
                List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, CredentialScheme.BEARER, List.of(),
                Duration.ofSeconds(1), null, null, CredentialScheme.TOKEN, null)).isInstanceOf(IllegalArgumentException.class);
    }
}
