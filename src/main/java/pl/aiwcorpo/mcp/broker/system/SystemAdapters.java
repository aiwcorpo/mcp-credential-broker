package pl.aiwcorpo.mcp.broker.system;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.Semaphore;
import java.util.function.Supplier;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;
import tools.jackson.databind.json.JsonMapper;

/** Builds the adapter objects of a stored system; the adapter object implements the interfaces of the capabilities its system has. */
public class SystemAdapters {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SystemAdapters.class);

    private final HttpClient http;
    private final JsonMapper json;
    private final OAuthClientSecrets clientSecrets;
    private final ServiceAccountKeys serviceAccountKeys;
    private final Clock clock;
    private final MeterRegistry meters;
    private final BrokerProperties.TokenExchangePolicy tokenExchangePolicy;
    private final UpstreamLimits limits;

    public SystemAdapters(HttpClient http, JsonMapper json, OAuthClientSecrets clientSecrets, ServiceAccountKeys serviceAccountKeys,
            Clock clock, MeterRegistry meters, BrokerProperties.TokenExchangePolicy tokenExchangePolicy, UpstreamLimits limits) {
        this.http = http;
        this.json = json;
        this.clientSecrets = clientSecrets;
        this.serviceAccountKeys = serviceAccountKeys;
        this.clock = clock;
        this.meters = meters;
        this.tokenExchangePolicy = tokenExchangePolicy;
        this.limits = limits;
    }

    public SystemRegistry.ConfiguredSystem build(SystemDefinition definition) {
        if (definition.agentsAllowed() && !definition.supportedTypes().contains(CredentialType.SERVICE_ACCOUNT)) {
            log.warn("System {} has agentsAllowed without service-account (written by something other than this broker's admin API):"
                    + " agents stay refused, humans are served", definition.id());
            definition = definition.withAgentsAllowed(false);
        }
        SystemRules.check(definition);
        BrokerProperties.SystemConfig config = definition.toConfig();
        String id = definition.id();
        Integer secretVersion = definition.secretVersion();
        Supplier<SecretValue> clientSecret = () -> clientSecrets.read(id, secretVersion);
        Duration timeout = limits.effectiveTimeout(config.timeout());
        if (!timeout.equals(config.timeout())) {
            log.warn("System {} has a timeout of {}, not below the refresh lock lease: calls use {}", id, config.timeout(), timeout);
        }
        Semaphore inFlight = limits.inFlight(id);
        Object adapter = switch (definition.adapter()) {
            case "gitlab" -> new GitLabAdapter(config.baseUrl(), timeout, config.oauth(), clientSecret, http, json, inFlight);
            case "atlassian-dc" -> new AtlassianDcAdapter(AtlassianDcAdapter.Product.valueOf(definition.product().toUpperCase(java.util.Locale.ROOT)),
                    config.baseUrl(), timeout, http, json, inFlight);
            case "opensearch" -> new OpenSearchAdapter(config.tokenExchange(), timeout, clientSecret, http, json, clock, meters, inFlight);
            case "generic-rest" -> new GenericRestAdapter(id, config.secretScheme(), serviceAccountKeys, config.baseUrl(), definition.whoami(), timeout,
                    http, json, inFlight);
            default -> throw new SystemRejectedException("adapter_unknown", "unknown adapter " + definition.adapter());
        };
        TokenExchanger exchanger = adapter instanceof TokenExchanger found ? found : null;
        if (exchanger != null && !tokenExchangePolicy.allows(definition.exchangeAudience())) {
            log.warn("System {} exchanges tokens for the audience {}, which broker.token-exchange.allowed-audiences does not allow:"
                    + " it is refused until the audience is allowed or the system is changed", id, definition.exchangeAudience());
            exchanger = subject -> {
                throw new UpstreamUnavailableException("the audience of this system is not allowed");
            };
        }
        return new SystemRegistry.ConfiguredSystem(id, config, adapter instanceof SystemAdapter whoami ? whoami : null,
                exchanger,
                adapter instanceof ServiceAccountSource source ? source : null, definition.etag(), definition.clientRevision(),
                definition.displayName(), definition.agentsAllowed());
    }
}
