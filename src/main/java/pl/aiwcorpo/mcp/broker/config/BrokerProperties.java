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
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
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
        @DefaultValue @Valid @NotNull Authenticator authenticator,
        @DefaultValue @Valid @NotNull Retention retention,
        @DefaultValue @Valid @NotNull RateLimits rateLimits,
        @DefaultValue @Valid @NotNull LostSecretBrake lostSecretBrake,
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
            @DefaultValue("1h") @NotNull Duration jwksMaxStale,
            @DefaultValue("5s") @NotNull Duration jwksFetchTimeout) {

        /**
         * Relations between the intervals: a refresh interval longer than maxStale would let healthy keys expire
         * before the next lookup refreshes them; a sub-second minimum interval would not protect the JWKS endpoint,
         * and one longer than the refresh interval would make the refresh interval meaningless. A fetch timeout
         * not shorter than the minimum interval would let a lookup that waited out one fetch start another at once.
         */
        @AssertTrue(message = "broker.gateway-jwt: jwks-refresh must be positive and not longer than jwks-max-stale, "
                + "jwks-min-refresh-interval must be between 1s and jwks-refresh, "
                + "jwks-fetch-timeout must be positive and shorter than jwks-min-refresh-interval")
        public boolean isJwksTimingConsistent() {
            if (jwksRefresh == null || jwksMinRefreshInterval == null || jwksMaxStale == null || jwksFetchTimeout == null) {
                return true;
            }
            return jwksRefresh.isPositive() && jwksRefresh.compareTo(jwksMaxStale) <= 0
                    && jwksMinRefreshInterval.compareTo(Duration.ofSeconds(1)) >= 0
                    && jwksMinRefreshInterval.compareTo(jwksRefresh) <= 0
                    && jwksFetchTimeout.isPositive() && jwksFetchTimeout.compareTo(jwksMinRefreshInterval) < 0;
        }
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
            @DefaultValue("mcp/service-accounts") @NotBlank String serviceAccountsPrefix,
            @DefaultValue("transit") @NotBlank String transitMount,
            @DefaultValue("mcp-credential-broker") @NotBlank String transitKey,
            @DefaultValue("5s") @NotNull Duration timeout) {
    }

    public record Redis(
            @DefaultValue("jti:mcp-credential-broker:") @NotBlank String jtiPrefix,
            @DefaultValue("credential.invalidated") @NotBlank String invalidationChannel) {
    }

    /**
     * TOTP authenticator (C4, CC-091, CC-092, CC-126). Seeds are encrypted by the Transit key {@code transitKey}
     * (same mount as the credentials) and stored under {@code pathPrefix}. The limits, the window and the enrollment
     * rules are fixed by the contract and are constants of {@code AuthenticatorLimits}, not configuration.
     */
    public record Authenticator(
            @DefaultValue("mcp-authenticators") @NotBlank String transitKey,
            @DefaultValue("mcp/authenticators") @NotBlank String pathPrefix,
            @DefaultValue("10") @Min(1) int enrollmentStartsPerHour,
            @DefaultValue("1m") @NotNull Duration sweepInterval,
            @DefaultValue("30m") @NotNull Duration orphanSweepInterval) {
    }

    /**
     * Removal of connections nobody uses (CC-155): a connection whose last use (its creation, when it was never
     * used) is older than {@code unusedAfter} is deleted like a disconnect would, by a job that runs every
     * {@code cleanupInterval}. The portal derives "about to expire" from {@code lastUsedAt} and {@code connectedAt}.
     */
    public record Retention(
            @DefaultValue("180d") @NotNull Duration unusedAfter,
            @DefaultValue("1h") @NotNull Duration cleanupInterval,
            @DefaultValue("100") @Min(1) int batchSize,
            @DefaultValue("1h") @NotNull Duration orphanSecretsAfter,
            @DefaultValue("6h") @NotNull Duration orphanSweepInterval,
            @DefaultValue("false") boolean orphanSweepDelete,
            @DefaultValue("50") @Min(1) int orphanMaxDeletesPerRun,
            @DefaultValue("0.2") @DecimalMin("0.0") @DecimalMax("1.0") double orphanMaxFraction,
            @DefaultValue("30m") @NotNull Duration purgeMarkerTtl) {
    }

    /**
     * Limits per {@code sub} on the OAuth operations of the portal (CC-156), counted in a fixed window in Redis. The
     * contract does not fix the values. The limit of authenticator enrollment starts is
     * {@link Authenticator#enrollmentStartsPerHour()}.
     */
    public record RateLimits(
            @DefaultValue("10") @Min(1) int oauthStarts,
            @DefaultValue("20") @Min(1) int oauthCompletions,
            @DefaultValue("1m") @NotNull Duration window,
            @DefaultValue("broker:rate:") @NotBlank String redisPrefix) {
    }

    /**
     * Stops marking connections whose secret is missing (CC-205) once more than {@code maxMarks} rows were marked within
     * {@code window}. A burst that large means the secret store, not the individual secrets, is wrong (a changed path
     * prefix, a store restored from an old state): the rows stay connected and recover when the store is fixed.
     */
    public record LostSecretBrake(
            @DefaultValue("10") @Min(1) int maxMarks,
            @DefaultValue("10m") @NotNull Duration window) {
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
            @DefaultValue("3s") @NotNull Duration refreshLockWait,
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

    /**
     * Token exchange of a system in the IdP (RFC 8693). {@code clientSecret} is a fallback for local development only,
     * like {@link OAuth#clientSecret()}; the secret belongs in OpenBao under {@code openbao.oauth-clients-prefix}.
     */
    public record TokenExchange(
            @NotBlank String clientId,
            String clientSecret,
            @NotNull URI tokenUrl,
            @NotBlank String audience,
            @DefaultValue("") List<String> scopes) {

        public TokenExchange {
            scopes = scopes == null ? List.of() : scopes.stream().filter(scope -> !scope.isBlank()).toList();
        }

        @Override
        public String toString() {
            return "TokenExchange[clientId=" + clientId + ", audience=" + audience + "]";
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
            @Valid OAuth oauth,
            @Valid TokenExchange tokenExchange,
            CredentialScheme userSecretScheme,
            Deployment deployment) {

        /** An unset list binds as one empty string; C4 wants an empty list. */
        public SystemConfig {
            oauthScopes = oauthScopes == null ? List.of() : oauthScopes.stream().filter(scope -> !scope.isBlank()).toList();
            if (userSecretScheme != null && userSecretScheme != CredentialScheme.BEARER && userSecretScheme != CredentialScheme.BASIC) {
                throw new IllegalArgumentException("user-secret-scheme is Bearer or Basic");
            }
            if (userSecretScheme == CredentialScheme.BASIC && (supportedTypes == null || !supportedTypes.contains(CredentialType.USER_SECRET))) {
                throw new IllegalArgumentException("user-secret-scheme Basic needs the user-secret type");
            }
        }

        /** True when a user gives a login and a password or token for this system (CC-222); false means a single token. */
        public boolean userSecretIsBasic() {
            return userSecretScheme == CredentialScheme.BASIC;
        }
    }

    /** Kind of installation of a target system, told to the portal by {@code GET /v1/systems} (CC-222). */
    public enum Deployment {
        DC("dc"), CLOUD("cloud");

        private final String wire;

        Deployment(String wire) {
            this.wire = wire;
        }

        public String wire() {
            return wire;
        }
    }
}
