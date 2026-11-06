package pl.aiwcorpo.mcp.broker.system;

import java.net.URI;
import java.time.Clock;
import java.util.Map;
import java.util.TreeMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.RequestIds;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;

/**
 * One-time move of the systems of a 1.x installation into the table: when the {@code broker.systems.*} properties are present,
 * nothing was imported before and the table is empty, every system of the properties is stored. The client secret is not
 * copied from anywhere unless the dev-only {@code client-secret} property is given (it is then written to OpenBao); a 1.x
 * installation already keeps it at the path the admin API uses. After that the properties are ignored and can be removed.
 */
public class LegacySystemImport {

    private static final Logger log = LoggerFactory.getLogger(LegacySystemImport.class);

    private final SystemRepository repository;
    private final OAuthClientSecrets clientSecrets;
    private final AuditLog audit;
    private final Clock clock;

    public LegacySystemImport(SystemRepository repository, OAuthClientSecrets clientSecrets, AuditLog audit, Clock clock) {
        this.repository = repository;
        this.clientSecrets = clientSecrets;
        this.audit = audit;
        this.clock = clock;
    }

    /** @return the number of systems stored */
    public int run(Map<String, BrokerProperties.SystemConfig> legacy) {
        if (legacy.isEmpty()) {
            return 0;
        }
        if (repository.importDone() || !repository.isEmpty()) {
            log.warn("broker.systems.* is ignored: the systems are stored in the database and managed through /v1/admin/systems."
                    + " Remove these properties.");
            return 0;
        }
        int stored = 0;
        for (Map.Entry<String, BrokerProperties.SystemConfig> entry : new TreeMap<>(legacy).entrySet()) {
            String id = entry.getKey();
            SystemDefinition definition = definition(id, entry.getValue());
            SystemRules.check(definition);
            if (repository.insert(definition, clock.instant())) {
                stored++;
                audit.event("admin_change", RequestIds.next(clock)).system(id).ok("system_imported");
            }
        }
        repository.markImported(clock.instant());
        log.warn("Imported {} systems from broker.systems.* into the database. These properties are no longer read; remove them.", stored);
        return stored;
    }

    private SystemDefinition definition(String id, BrokerProperties.SystemConfig config) {
        SystemDefinition.Oauth oauth = null;
        String audience = null;
        String devSecret = null;
        if (config.tokenExchange() != null) {
            BrokerProperties.TokenExchange exchange = config.tokenExchange();
            oauth = new SystemDefinition.Oauth(exchange.clientId(), exchange.tokenUrl(), exchange.tokenUrl(), null, exchange.scopes());
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
        boolean secretSet = false;
        if (oauth != null) {
            if (devSecret != null && !devSecret.isBlank()) {
                clientSecrets.write(id, SecretValue.of(devSecret));
                secretSet = true;
            } else {
                secretSet = clientSecrets.exists(id);
            }
        }
        return new SystemDefinition(id, config.baseUrl(), config.adapter(), config.supportedTypes(), config.defaultType(),
                config.secretScheme(), oauth, secretSet, config.timeout(), audience, config.userSecretScheme(), config.deployment(),
                SystemDefinition.newEtag());
    }

    private static URI under(URI base, String path) {
        String text = base.toString();
        return URI.create((text.endsWith("/") ? text.substring(0, text.length() - 1) : text) + path);
    }
}
