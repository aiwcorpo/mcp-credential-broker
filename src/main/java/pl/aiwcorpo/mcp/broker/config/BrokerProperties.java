package pl.aiwcorpo.mcp.broker.config;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;

@Validated
@ConfigurationProperties("broker")
public record BrokerProperties(
        @DefaultValue("mcp-credential-broker") @NotBlank String componentId,
        @NotNull URI portalBaseUrl,
        @DefaultValue("60") @Min(0) @Max(60) int cacheTtlSeconds,
        @DefaultValue("7d") @NotNull Duration expiringThreshold,
        @DefaultValue("16384") @Min(1024) int maxRequestBytes,
        @DefaultValue("false") boolean allowPlainHttp,
        @Valid @NotNull GatewayJwt gatewayJwt,
        @Valid @NotNull BffToken bffToken,
        @Valid @NotNull OpenBao openbao,
        @Valid @NotNull Redis redis,
        @Valid @NotNull OAuthFlow oauthFlow,
        @NotEmpty Map<String, @Valid SystemConfig> systems) {

    /** Internal JWT from the gateway (C2). Exactly one of jwksUri and jwksFile is set. */
    public record GatewayJwt(
            @DefaultValue("https://mcp-gateway.internal") @NotBlank String issuer,
            @DefaultValue("mcp-credential-broker") @NotBlank String audience,
            URI jwksUri,
            String jwksFile,
            String tlsName,
            @DefaultValue("false") boolean allowTestKeys,
            @DefaultValue("30s") @NotNull Duration clockSkew,
            @DefaultValue("60s") @NotNull Duration maxLifetime,
            @DefaultValue("5m") @NotNull Duration jwksRefresh,
            @DefaultValue("10s") @NotNull Duration jwksMinRefreshInterval,
            @DefaultValue("1h") @NotNull Duration jwksMaxStale) {
    }

    /** User token of the portal BFF, exchanged in the IdP for aud=mcp-credential-broker (C4). */
    public record BffToken(
            @NotBlank String issuer,
            @NotNull URI jwksUri,
            @DefaultValue("mcp-credential-broker") @NotBlank String audience,
            @DefaultValue("mcp-portal-bff") @NotEmpty Set<String> allowedAzp,
            @DefaultValue("preferred_username") @NotBlank String usernameClaim) {
    }

    public record OpenBao(
            @NotNull URI address,
            @NotBlank String roleId,
            @NotBlank String secretId,
            @DefaultValue("secret") @NotBlank String kvMount,
            @DefaultValue("mcp/connections") @NotBlank String pathPrefix,
            @DefaultValue("mcp/oauth-clients") @NotBlank String oauthClientsPrefix,
            @DefaultValue("transit") @NotBlank String transitMount,
            @DefaultValue("mcp-credential-broker") @NotBlank String transitKey,
            @DefaultValue("5s") @NotNull Duration timeout) {
    }

    public record Redis(
            @DefaultValue("jti:mcp-credential-broker:") @NotBlank String jtiPrefix,
            @DefaultValue("credential.invalidated") @NotBlank String invalidationChannel) {
    }

    /**
     * Authorization code flow (C4 oauth/start, oauth/complete) and token refresh. A token is refreshed when it
     * has less than {@code refreshMargin} left, which must exceed {@code cacheTtlSeconds} so that a token
     * handed to the gateway outlives the gateway's cache. The background sweep refreshes tokens that would
     * need it within {@code sweepWindow}.
     */
    public record OAuthFlow(
            @DefaultValue("10m") @NotNull Duration flowTtl,
            @DefaultValue("2m") @NotNull Duration refreshMargin,
            @DefaultValue("5m") @NotNull Duration sweepWindow,
            @DefaultValue("1m") @NotNull Duration sweepInterval,
            @DefaultValue("5s") @NotNull Duration refreshLockWait,
            @DefaultValue("60s") @NotNull Duration refreshLockLease,
            @DefaultValue("broker:oauth:") @NotBlank String redisPrefix) {
    }

    /**
     * OAuth client of a system. The client secret is read from OpenBao ({@code openbao.oauth-clients-prefix});
     * {@code clientSecret} here is a fallback for local development only and is refused unless
     * {@code allow-plain-http} is set. Endpoints default to the standard paths under the system's base URL;
     * {@code authorizeUrl} is the address the user's browser opens, which can differ from the one the broker
     * reaches the system on.
     */
    public record OAuth(
            @NotBlank String clientId,
            String clientSecret,
            URI authorizeUrl,
            URI tokenUrl,
            URI revokeUrl) {

        @Override
        public String toString() {
            return "OAuth[clientId=" + clientId + "]";
        }
    }

    /** One target system. */
    public record SystemConfig(
            @NotNull URI baseUrl,
            @NotBlank String adapter,
            @NotEmpty List<CredentialType> supportedTypes,
            @NotNull CredentialType defaultType,
            @DefaultValue("Bearer") @NotNull CredentialScheme secretScheme,
            @DefaultValue("") List<String> oauthScopes,
            @DefaultValue("5s") @NotNull Duration timeout,
            @Valid OAuth oauth) {

        /** An unset list binds as one empty string; C4 wants an empty list. */
        public SystemConfig {
            oauthScopes = oauthScopes == null ? List.of() : oauthScopes.stream().filter(scope -> !scope.isBlank()).toList();
        }
    }
}
