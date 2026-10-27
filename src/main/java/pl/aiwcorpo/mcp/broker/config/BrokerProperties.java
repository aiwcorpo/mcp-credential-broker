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
            @DefaultValue("transit") @NotBlank String transitMount,
            @DefaultValue("mcp-credential-broker") @NotBlank String transitKey,
            @DefaultValue("5s") @NotNull Duration timeout) {
    }

    public record Redis(
            @DefaultValue("jti:mcp-credential-broker:") @NotBlank String jtiPrefix,
            @DefaultValue("credential.invalidated") @NotBlank String invalidationChannel) {
    }

    /**
     * One target system. {@code identityClaim} names the SSO claim compared with the backend identity
     * (C4.1): {@code preferred_username} against the backend user name, {@code email} against its e-mail.
     */
    public record SystemConfig(
            @NotNull URI baseUrl,
            @NotBlank String adapter,
            @NotEmpty List<CredentialType> supportedTypes,
            @NotNull CredentialType defaultType,
            @DefaultValue("Bearer") @NotNull CredentialScheme secretScheme,
            @DefaultValue("preferred_username") @NotBlank String identityClaim,
            @DefaultValue("") List<String> oauthScopes,
            @DefaultValue("5s") @NotNull Duration timeout) {
    }
}
