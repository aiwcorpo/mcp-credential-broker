package pl.aiwcorpo.mcp.broker.system;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;

/**
 * One stored system. {@code oauth} is the OAuth client for user-oauth, and the client of the identity provider for
 * token-exchange (where {@code authorizeUrl} has no use). {@code timeout}, {@code userSecretScheme}, {@code deployment}
 * and {@code exchangeAudience} are not in the admin API; they are filled by the import of the 1.x properties and kept when a
 * system is replaced.
 */
public record SystemDefinition(
        String id,
        URI baseUrl,
        String adapter,
        List<CredentialType> supportedTypes,
        CredentialType defaultType,
        CredentialScheme secretScheme,
        Oauth oauth,
        boolean clientSecretSet,
        Duration timeout,
        String exchangeAudience,
        CredentialScheme userSecretScheme,
        BrokerProperties.Deployment deployment,
        String etag) {

    public record Oauth(String clientId, URI authorizeUrl, URI tokenUrl, URI revokeUrl, List<String> scopes) {

        public Oauth {
            scopes = scopes == null ? List.of() : List.copyOf(scopes);
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    /** A random opaque revision, regenerated on every write: 22 characters of the base64url alphabet. */
    public static String newEtag() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public SystemDefinition withEtag(String newEtag) {
        return new SystemDefinition(id, baseUrl, adapter, supportedTypes, defaultType, secretScheme, oauth, clientSecretSet,
                timeout, exchangeAudience, userSecretScheme, deployment, newEtag);
    }

    public SystemDefinition withClientSecretSet(boolean set) {
        return new SystemDefinition(id, baseUrl, adapter, supportedTypes, defaultType, secretScheme, oauth, set,
                timeout, exchangeAudience, userSecretScheme, deployment, etag);
    }

    public boolean usesClientSecret() {
        return oauth != null;
    }

    /** The runtime shape the adapters and services work with; the client secret is never part of it. */
    public BrokerProperties.SystemConfig toConfig() {
        boolean exchange = supportedTypes.contains(CredentialType.TOKEN_EXCHANGE);
        BrokerProperties.OAuth userOauth = oauth == null || exchange ? null
                : new BrokerProperties.OAuth(oauth.clientId(), null, oauth.authorizeUrl(), oauth.tokenUrl(), oauth.revokeUrl());
        BrokerProperties.TokenExchange tokenExchange = oauth == null || !exchange ? null
                : new BrokerProperties.TokenExchange(oauth.clientId(), null, oauth.tokenUrl(),
                        exchangeAudience == null ? id : exchangeAudience, oauth.scopes());
        return new BrokerProperties.SystemConfig(baseUrl, adapter, supportedTypes, defaultType, secretScheme,
                exchange || oauth == null ? List.of() : oauth.scopes(), timeout == null ? Duration.ofSeconds(5) : timeout,
                userOauth, tokenExchange, userSecretScheme, deployment);
    }
}
