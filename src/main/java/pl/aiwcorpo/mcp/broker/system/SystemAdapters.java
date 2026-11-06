package pl.aiwcorpo.mcp.broker.system;

import java.net.http.HttpClient;
import java.time.Clock;
import java.util.function.Supplier;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;
import tools.jackson.databind.json.JsonMapper;

/** Builds the adapter objects of a stored system; the adapter object implements the interfaces of the capabilities its system has. */
public class SystemAdapters {

    private final HttpClient http;
    private final JsonMapper json;
    private final OAuthClientSecrets clientSecrets;
    private final ServiceAccountKeys serviceAccountKeys;
    private final Clock clock;
    private final MeterRegistry meters;

    public SystemAdapters(HttpClient http, JsonMapper json, OAuthClientSecrets clientSecrets, ServiceAccountKeys serviceAccountKeys,
            Clock clock, MeterRegistry meters) {
        this.http = http;
        this.json = json;
        this.clientSecrets = clientSecrets;
        this.serviceAccountKeys = serviceAccountKeys;
        this.clock = clock;
        this.meters = meters;
    }

    public SystemRegistry.ConfiguredSystem build(SystemDefinition definition) {
        SystemRules.check(definition);
        BrokerProperties.SystemConfig config = definition.toConfig();
        String id = definition.id();
        String revision = definition.etag();
        Supplier<SecretValue> clientSecret = () -> clientSecrets.clientSecret(id, revision);
        Object adapter = switch (definition.adapter()) {
            case "gitlab" -> new GitLabAdapter(config.baseUrl(), config.timeout(), config.oauth(), clientSecret, http, json);
            case "atlassian-dc" -> new AtlassianDcAdapter(config.baseUrl(), config.timeout(), http, json);
            case "opensearch" -> new OpenSearchAdapter(config.tokenExchange(), config.timeout(), clientSecret, http, json, clock, meters);
            case "generic-rest" -> new GenericRestAdapter(id, config.secretScheme(), serviceAccountKeys);
            default -> throw new SystemRejectedException("adapter_unknown", "unknown adapter " + definition.adapter());
        };
        return new SystemRegistry.ConfiguredSystem(id, config, adapter instanceof SystemAdapter whoami ? whoami : null,
                adapter instanceof TokenExchanger exchanger ? exchanger : null,
                adapter instanceof ServiceAccountSource source ? source : null, definition.etag());
    }
}
