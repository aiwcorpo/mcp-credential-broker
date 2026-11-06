package pl.aiwcorpo.mcp.broker.support;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.http.HttpClient;
import java.time.Clock;
import java.util.List;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;
import pl.aiwcorpo.mcp.broker.system.SystemAdapters;
import pl.aiwcorpo.mcp.broker.system.SystemDefinition;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import pl.aiwcorpo.mcp.broker.system.SystemRepository;
import tools.jackson.databind.json.JsonMapper;

/** A registry over one system, for unit tests that have no database. */
public final class TestRegistries {

    private TestRegistries() {
    }

    public static SystemRegistry of(String id, BrokerProperties.SystemConfig config) {
        SystemRepository repository = mock(SystemRepository.class);
        SystemDefinition.Oauth oauth = config.oauth() == null ? null : new SystemDefinition.Oauth(config.oauth().clientId(),
                config.oauth().authorizeUrl(), config.oauth().tokenUrl(), config.oauth().revokeUrl(), config.oauthScopes());
        when(repository.findAll()).thenReturn(List.of(new SystemDefinition(id, config.baseUrl(), config.adapter(),
                config.supportedTypes(), config.defaultType(), config.secretScheme(), oauth, false, config.timeout(), null,
                config.userSecretScheme(), config.deployment(), "etag-" + id)));
        SystemAdapters adapters = new SystemAdapters(HttpClient.newHttpClient(), JsonMapper.builder().build(),
                mock(OAuthClientSecrets.class), mock(ServiceAccountKeys.class), Clock.systemUTC(), new SimpleMeterRegistry());
        return new SystemRegistry(repository, adapters);
    }
}
