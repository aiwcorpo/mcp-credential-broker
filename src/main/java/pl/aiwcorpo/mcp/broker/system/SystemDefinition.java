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
 * One stored system. {@code oauth} is the OAuth client for user-oauth, and the client credentials with the identity
 * provider for token-exchange (where {@code authorizeUrl} is absent and {@code tokenUrl} is the endpoint of the configured
 * identity provider, not a value of the administrator). {@code secretVersion} is the KV version of the client secret that
 * belongs to this row. {@code clientRevision} moves only when the system points somewhere else; a grant is issued under one
 * revision and never used with another. {@code deployment} is not in the admin API: it comes from the import of 1.x and is
 * kept when a system is replaced.
 */
public record SystemDefinition(
        String id,
        URI baseUrl,
        String adapter,
        String product,
        List<CredentialType> supportedTypes,
        CredentialType defaultType,
        CredentialScheme secretScheme,
        Oauth oauth,
        Integer secretVersion,
        Duration timeout,
        String exchangeAudience,
        CredentialScheme userSecretScheme,
        BrokerProperties.Deployment deployment,
        String etag,
        String clientRevision) {

    public record Oauth(String clientId, URI authorizeUrl, URI tokenUrl, URI revokeUrl, List<String> scopes) {

        public Oauth {
            scopes = scopes == null ? List.of() : List.copyOf(scopes);
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    /** A random opaque token: 22 characters of the base64url alphabet. */
    public static String newToken() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public boolean clientSecretSet() {
        return secretVersion != null;
    }

    public SystemDefinition withEtag(String newEtag) {
        return new SystemDefinition(id, baseUrl, adapter, product, supportedTypes, defaultType, secretScheme, oauth, secretVersion,
                timeout, exchangeAudience, userSecretScheme, deployment, newEtag, clientRevision);
    }

    public SystemDefinition withSecretVersion(Integer version) {
        return new SystemDefinition(id, baseUrl, adapter, product, supportedTypes, defaultType, secretScheme, oauth, version,
                timeout, exchangeAudience, userSecretScheme, deployment, etag, clientRevision);
    }

    public SystemDefinition withClientRevision(String revision) {
        return new SystemDefinition(id, baseUrl, adapter, product, supportedTypes, defaultType, secretScheme, oauth, secretVersion,
                timeout, exchangeAudience, userSecretScheme, deployment, etag, revision);
    }

    public SystemDefinition withTimeout(Duration newTimeout) {
        return new SystemDefinition(id, baseUrl, adapter, product, supportedTypes, defaultType, secretScheme, oauth, secretVersion,
                newTimeout, exchangeAudience, userSecretScheme, deployment, etag, clientRevision);
    }

    /** Whether the other definition points to the same places with the same client: what decides if connections survive. */
    public boolean pointsSameAs(SystemDefinition other) {
        Oauth mine = oauth;
        Oauth theirs = other.oauth;
        return baseUrl.equals(other.baseUrl)
                && (mine == null ? theirs == null : theirs != null && mine.clientId().equals(theirs.clientId())
                        && java.util.Objects.equals(mine.authorizeUrl(), theirs.authorizeUrl())
                        && java.util.Objects.equals(mine.tokenUrl(), theirs.tokenUrl())
                        && java.util.Objects.equals(mine.revokeUrl(), theirs.revokeUrl()));
    }

    /** The runtime shape the adapters and services work with; the client secret is never part of it. */
    public BrokerProperties.SystemConfig toConfig() {
        boolean exchange = supportedTypes.contains(CredentialType.TOKEN_EXCHANGE);
        BrokerProperties.OAuth userOauth = oauth == null || exchange ? null
                : new BrokerProperties.OAuth(oauth.clientId(), null, oauth.authorizeUrl(), oauth.tokenUrl(), oauth.revokeUrl());
        BrokerProperties.TokenExchange tokenExchange = oauth == null || !exchange ? null
                : new BrokerProperties.TokenExchange(oauth.clientId(), null, oauth.tokenUrl(), exchangeAudience, oauth.scopes());
        return new BrokerProperties.SystemConfig(baseUrl, adapter, supportedTypes, defaultType, secretScheme,
                exchange || oauth == null ? List.of() : oauth.scopes(), timeout == null ? Duration.ofSeconds(5) : timeout,
                userOauth, tokenExchange, userSecretScheme, deployment);
    }
}
