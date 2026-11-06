package pl.aiwcorpo.mcp.broker.system;

import java.net.URI;
import java.time.Clock;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.transaction.support.TransactionTemplate;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.RequestIds;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.ConnectionRepository;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;

/**
 * One-time move of the systems of a 1.x installation into the table. On the first start of 2.0 the broker takes a database
 * lock, and when nothing was imported before it stores the systems of the {@code broker.systems.*} properties (only into an
 * empty table) and in every case writes the marker, in one transaction. From then on the properties are ignored, also after
 * every system was deleted. The client secret is copied from where 1.x kept it ({@code mcp/oauth-clients/<system>}) to the
 * path of the admin API, or written from the dev only {@code client-secret} property. Connections of 1.x are adopted under the
 * revision of their system.
 */
public class LegacySystemImport {

    private static final Logger log = LoggerFactory.getLogger(LegacySystemImport.class);

    private final SystemRepository repository;
    private final ConnectionRepository connections;
    private final OAuthClientSecrets clientSecrets;
    private final AuditLog audit;
    private final Clock clock;
    private final TransactionTemplate transaction;
    private final URI idpTokenUrl;

    public LegacySystemImport(SystemRepository repository, ConnectionRepository connections, OAuthClientSecrets clientSecrets,
            AuditLog audit, Clock clock, TransactionTemplate transaction, URI idpTokenUrl) {
        this.repository = repository;
        this.connections = connections;
        this.clientSecrets = clientSecrets;
        this.audit = audit;
        this.clock = clock;
        this.transaction = transaction;
        this.idpTokenUrl = idpTokenUrl;
    }

    /** @return the number of systems stored */
    public int run(Map<String, BrokerProperties.SystemConfig> legacy) {
        for (String id : legacy.keySet()) {
            if (!SystemIds.isValid(id)) {
                throw new IllegalStateException("broker.systems." + id + ": not a valid system id (lower case letters and digits,"
                        + " 2 to 31 characters, starting with a letter, and not one of the reserved names "
                        + new java.util.TreeSet<>(SystemIds.RESERVED) + "); rename it or remove it");
            }
        }
        Integer stored = transaction.execute(status -> {
            repository.lockForImport();
            if (repository.importDone()) {
                if (!legacy.isEmpty()) {
                    log.warn("broker.systems.* is ignored: the systems are in the database and managed through /v1/admin/systems."
                            + " Remove these properties.");
                }
                return 0;
            }
            int count = 0;
            if (!legacy.isEmpty() && !repository.isEmpty()) {
                log.warn("broker.systems.* is ignored: the database already has systems. Remove these properties.");
            } else {
                for (Map.Entry<String, BrokerProperties.SystemConfig> entry : new TreeMap<>(legacy).entrySet()) {
                    SystemDefinition definition = definition(entry.getKey(), entry.getValue());
                    SystemRules.check(definition);
                    if (repository.insert(definition, clock.instant())) {
                        connections.adoptRevision(definition.id(), definition.clientRevision());
                        audit.event("admin_change", RequestIds.next(clock)).systemBeingChanged(definition.id()).ok("system_imported");
                        count++;
                    }
                }
            }
            repository.markImported(clock.instant());
            if (count > 0) {
                log.warn("Imported {} systems from broker.systems.* into the database. These properties are no longer read;"
                        + " remove them.", count);
            }
            return count;
        });
        return stored == null ? 0 : stored;
    }

    private SystemDefinition definition(String id, BrokerProperties.SystemConfig config) {
        SystemDefinition.Oauth oauth = null;
        String audience = null;
        String devSecret = null;
        if (config.tokenExchange() != null) {
            BrokerProperties.TokenExchange exchange = config.tokenExchange();
            if (!exchange.tokenUrl().equals(idpTokenUrl)) {
                log.warn("System {}: its token-exchange token-url is not used any more; the token endpoint of the identity provider"
                        + " of the broker ({}) is.", id, idpTokenUrl);
            }
            oauth = new SystemDefinition.Oauth(exchange.clientId(), null, idpTokenUrl, null, exchange.scopes());
            audience = exchange.audience();
            devSecret = exchange.clientSecret();
        } else if (config.oauth() != null && config.supportedTypes().contains(CredentialType.USER_OAUTH)) {
            BrokerProperties.OAuth client = config.oauth();
            oauth = new SystemDefinition.Oauth(client.clientId(),
                    client.authorizeUrl() != null ? client.authorizeUrl() : under(config.baseUrl(), "/oauth/authorize"),
                    client.tokenUrl() != null ? client.tokenUrl() : under(config.baseUrl(), "/oauth/token"),
                    client.revokeUrl(), config.oauthScopes());
            devSecret = client.clientSecret();
        }
        Integer secretVersion = null;
        if (oauth != null) {
            Optional<SecretValue> secret = devSecret != null && !devSecret.isBlank() ? Optional.of(SecretValue.of(devSecret))
                    : clientSecrets.readLegacy(id);
            if (secret.isPresent()) {
                secretVersion = clientSecrets.write(id, secret.get());
            }
        }
        return new SystemDefinition(id, config.baseUrl(), config.adapter(), product(id, config), config.supportedTypes(),
                config.defaultType(), config.secretScheme(), oauth, secretVersion, config.timeout(), audience,
                config.userSecretScheme(), config.deployment(), SystemDefinition.newToken(), SystemDefinition.newToken());
    }

    /** 1.x knew the product from the id of the system; 2.0 asks for it, so only those two ids can be carried over. */
    private static String product(String id, BrokerProperties.SystemConfig config) {
        if (!"atlassian-dc".equals(config.adapter())) {
            return null;
        }
        if ("jira".equals(id) || "confluence".equals(id)) {
            return id;
        }
        throw new SystemRejectedException("product_required", "broker.systems." + id
                + ": an atlassian-dc system needs a product (jira or confluence); create it through /v1/admin/systems instead");
    }

    private static URI under(URI base, String path) {
        String text = base.toString();
        return URI.create((text.endsWith("/") ? text.substring(0, text.length() - 1) : text) + path);
    }
}
