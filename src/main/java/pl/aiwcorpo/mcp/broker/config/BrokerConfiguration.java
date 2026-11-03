package pl.aiwcorpo.mcp.broker.config;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;

import javax.net.ssl.SSLContext;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import io.micrometer.core.instrument.MeterRegistry;
import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.BffTokenVerifier;
import pl.aiwcorpo.mcp.broker.auth.CallerAuthenticationFilter;
import pl.aiwcorpo.mcp.broker.auth.GatewayKeys;
import pl.aiwcorpo.mcp.broker.auth.InternalJwtVerifier;
import pl.aiwcorpo.mcp.broker.auth.JwksGatewayKeys;
import pl.aiwcorpo.mcp.broker.auth.RedisReplayGuard;
import pl.aiwcorpo.mcp.broker.auth.SubjectTokenVerifier;
import pl.aiwcorpo.mcp.broker.auth.ReplayGuard;
import pl.aiwcorpo.mcp.broker.authenticator.AuthenticatorSeedStore;
import pl.aiwcorpo.mcp.broker.authenticator.AuthenticatorSweepJob;
import pl.aiwcorpo.mcp.broker.authenticator.AuthenticatorService;
import pl.aiwcorpo.mcp.broker.authenticator.OpenBaoAuthenticatorSeedStore;
import pl.aiwcorpo.mcp.broker.credential.ConnectionRepository;
import pl.aiwcorpo.mcp.broker.credential.ConnectionStore;
import pl.aiwcorpo.mcp.broker.credential.CredentialService;
import pl.aiwcorpo.mcp.broker.credential.LostSecretSignal;
import pl.aiwcorpo.mcp.broker.credential.OAuthRefreshJob;
import pl.aiwcorpo.mcp.broker.credential.OffboardingService;
import pl.aiwcorpo.mcp.broker.credential.UnusedConnectionCleanupJob;
import pl.aiwcorpo.mcp.broker.credential.OAuthService;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.event.RedisInvalidationPublisher;
import pl.aiwcorpo.mcp.broker.oauth.OAuthFlowStore;
import pl.aiwcorpo.mcp.broker.oauth.RateLimiter;
import pl.aiwcorpo.mcp.broker.oauth.RedisOAuthFlowStore;
import pl.aiwcorpo.mcp.broker.oauth.RefreshLock;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.OpenBaoClient;
import pl.aiwcorpo.mcp.broker.secret.OpenBaoSecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import tools.jackson.databind.json.JsonMapper;

@Configuration(proxyBeanMethods = false)
@EnableScheduling
@EnableConfigurationProperties(BrokerProperties.class)
public class BrokerConfiguration {

    /** SSL bundle of the broker (keystore + internal CA); its trust material is reused for outgoing TLS. */
    public static final String SSL_BUNDLE = "broker";

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    AuditLog auditLog(BrokerProperties properties, Clock clock) {
        return new AuditLog(properties.componentId(), clock);
    }

    @Bean
    GatewayKeys gatewayKeys(BrokerProperties properties, SslBundles sslBundles, Clock clock) {
        BrokerProperties.GatewayJwt config = properties.gatewayJwt();
        boolean hasUri = config.jwksUri() != null && !config.jwksUri().toString().isBlank();
        boolean hasFile = config.jwksFile() != null && !config.jwksFile().isBlank();
        if (hasUri == hasFile) {
            throw new IllegalStateException("set exactly one of broker.gateway-jwt.jwks-uri and broker.gateway-jwt.jwks-file");
        }
        if (hasFile) {
            return JwksGatewayKeys.fromFile(Path.of(config.jwksFile()), clock);
        }
        if (config.tlsName() != null && !config.tlsName().isBlank() && "https".equals(config.jwksUri().getScheme())
                && !config.tlsName().equalsIgnoreCase(config.jwksUri().getHost())) {
            // The JDK client verifies the certificate against the URI host; a different expected name
            // (CC-035) could not be enforced, so refuse to start instead of silently checking the wrong name.
            throw new IllegalStateException("broker.gateway-jwt.jwks-uri host must equal broker.gateway-jwt.tls-name");
        }
        requireTls(config.jwksUri(), "broker.gateway-jwt.jwks-uri", properties.allowPlainHttp());
        return JwksGatewayKeys.fromUri(config.jwksUri(), internalClient(sslBundles), config.jwksFetchTimeout(), clock,
                config.jwksRefresh(), config.jwksMinRefreshInterval(), config.jwksMaxStale());
    }

    @Bean
    ReplayGuard replayGuard(StringRedisTemplate redis, BrokerProperties properties) {
        return new RedisReplayGuard(redis, properties.redis().jtiPrefix());
    }

    @Bean
    InternalJwtVerifier internalJwtVerifier(BrokerProperties properties, GatewayKeys keys, ReplayGuard replayGuard, Clock clock,
            Environment environment) {
        BrokerProperties.GatewayJwt config = properties.gatewayJwt();
        return new InternalJwtVerifier(config.issuer(), config.audience(), keys, replayGuard, clock,
                config.clockSkew(), config.maxLifetime(), config.allowTestKeys(), environment.acceptsProfiles(Profiles.of("devstack")));
    }

    @Bean
    BffTokenVerifier bffTokenVerifier(BrokerProperties properties, SslBundles sslBundles) {
        requireTls(properties.bffToken().jwksUri(), "broker.bff-token.jwks-uri", properties.allowPlainHttp());
        return BffTokenVerifier.create(properties.bffToken(), internalClient(sslBundles));
    }

    @Bean
    SubjectTokenVerifier subjectTokenVerifier(BrokerProperties properties, SslBundles sslBundles) {
        return SubjectTokenVerifier.create(properties.bffToken(), properties.gatewayJwt().clockSkew(), internalClient(sslBundles));
    }

    @Bean
    FilterRegistrationBean<CallerAuthenticationFilter> callerAuthenticationFilter(InternalJwtVerifier gatewayTokens,
            BffTokenVerifier bffTokens, AuditLog audit, JsonMapper json, Clock clock, BrokerProperties properties) {
        FilterRegistrationBean<CallerAuthenticationFilter> registration = new FilterRegistrationBean<>(
                new CallerAuthenticationFilter(gatewayTokens, bffTokens, audit, json, clock, properties.maxRequestBytes()));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        registration.addUrlPatterns("/*");
        return registration;
    }

    @Bean
    OpenBaoClient openBaoClient(BrokerProperties properties, SslBundles sslBundles, JsonMapper json) {
        BrokerProperties.OpenBao config = properties.openbao();
        requireTls(config.address(), "broker.openbao.address", properties.allowPlainHttp());
        // The token lease runs on OpenBao's wall clock; the application Clock bean is a seam for business time only.
        return new OpenBaoClient(config, internalClient(sslBundles), json, Clock.systemUTC());
    }

    @Bean
    SecretStore secretStore(BrokerProperties properties, OpenBaoClient client, JsonMapper json) {
        return new OpenBaoSecretStore(client, properties.openbao(), json);
    }

    @Bean
    OAuthClientSecrets oauthClientSecrets(BrokerProperties properties, OpenBaoClient client, Clock clock) {
        return new OAuthClientSecrets(client, properties.openbao().kvMount(), properties.openbao().oauthClientsPrefix(), clock);
    }

    @Bean
    ServiceAccountKeys serviceAccountKeys(BrokerProperties properties, OpenBaoClient client, Clock clock) {
        return new ServiceAccountKeys(client, properties.openbao().kvMount(), properties.openbao().serviceAccountsPrefix(), clock);
    }

    @Bean
    SystemRegistry systemRegistry(BrokerProperties properties, SslBundles sslBundles, JsonMapper json,
            OAuthClientSecrets clientSecrets, ServiceAccountKeys serviceAccountKeys, Clock clock, MeterRegistry meters) {
        requireTls(properties.portalBaseUrl(), "broker.portal-base-url", properties.allowPlainHttp());
        properties.systems().forEach((id, system) -> {
            requireTls(system.baseUrl(), "broker.systems." + id + ".base-url", properties.allowPlainHttp());
            if (system.oauth() != null) {
                if (system.oauth().clientSecret() != null && !system.oauth().clientSecret().isBlank() && !properties.allowPlainHttp()) {
                    throw new IllegalStateException("broker.systems." + id + ".oauth.client-secret is for local development only"
                            + " (broker.allow-plain-http); the client secret belongs in OpenBao under "
                            + properties.openbao().oauthClientsPrefix() + "/" + id);
                }
                requireTls(system.oauth().authorizeUrl(), "broker.systems." + id + ".oauth.authorize-url", properties.allowPlainHttp());
                requireTls(system.oauth().tokenUrl(), "broker.systems." + id + ".oauth.token-url", properties.allowPlainHttp());
                requireTls(system.oauth().revokeUrl(), "broker.systems." + id + ".oauth.revoke-url", properties.allowPlainHttp());
            }
            if (system.tokenExchange() != null) {
                if (system.tokenExchange().clientSecret() != null && !system.tokenExchange().clientSecret().isBlank()
                        && !properties.allowPlainHttp()) {
                    throw new IllegalStateException("broker.systems." + id + ".token-exchange.client-secret is for local development only"
                            + " (broker.allow-plain-http); the client secret belongs in OpenBao under "
                            + properties.openbao().oauthClientsPrefix() + "/" + id);
                }
                requireTls(system.tokenExchange().tokenUrl(), "broker.systems." + id + ".token-exchange.token-url",
                        properties.allowPlainHttp());
            }
        });
        return new SystemRegistry(properties.systems(), internalClient(sslBundles), json, clientSecrets, serviceAccountKeys, clock, meters);
    }

    @Bean
    ConnectionRepository connectionRepository(JdbcClient jdbc) {
        return new ConnectionRepository(jdbc);
    }

    @Bean
    InvalidationPublisher invalidationPublisher(StringRedisTemplate redis, BrokerProperties properties, JsonMapper json) {
        return new RedisInvalidationPublisher(redis, properties.redis().invalidationChannel(), json);
    }

    @Bean
    OAuthFlowStore oauthFlowStore(StringRedisTemplate redis, BrokerProperties properties, JsonMapper json) {
        return new RedisOAuthFlowStore(redis, properties.oauthFlow().redisPrefix(), json);
    }

    @Bean
    RefreshLock refreshLock(StringRedisTemplate redis, BrokerProperties properties) {
        return new RefreshLock(redis, properties.oauthFlow().redisPrefix(), properties.oauthFlow().refreshLockLease());
    }

    @Bean
    RateLimiter rateLimiter(StringRedisTemplate redis, BrokerProperties properties) {
        return new RateLimiter(redis, properties.rateLimits().redisPrefix(), properties.rateLimits().window());
    }

    @Bean
    OAuthService oauthService(SystemRegistry systems, ConnectionRepository connections, SecretStore secrets,
            InvalidationPublisher invalidations, OAuthFlowStore flows, RefreshLock lock, AuditLog audit, Clock clock,
            BrokerProperties properties, RateLimiter rateLimiter, LostSecretSignal lostSecrets) {
        if (properties.oauthFlow().refreshMargin().compareTo(Duration.ofSeconds(properties.cacheTtlSeconds())) <= 0) {
            throw new IllegalStateException("broker.oauth-flow.refresh-margin must exceed broker.cache-ttl-seconds");
        }
        return new OAuthService(systems, connections, secrets, new ConnectionStore(connections, secrets, invalidations, clock),
                flows, lock, audit, clock, portalCallback(properties), properties.oauthFlow(), rateLimiter, properties.rateLimits(),
                lostSecrets);
    }

    @Bean
    LostSecretSignal lostSecretSignal(Clock clock, MeterRegistry meters, BrokerProperties properties) {
        return new LostSecretSignal(clock, meters, properties.lostSecretBrake().maxMarks(), properties.lostSecretBrake().window());
    }

    @Bean
    OAuthRefreshJob oauthRefreshJob(OAuthService oauth) {
        return new OAuthRefreshJob(oauth);
    }

    @Bean
    AuthenticatorSeedStore authenticatorSeedStore(BrokerProperties properties, OpenBaoClient client, JsonMapper json) {
        return new OpenBaoAuthenticatorSeedStore(client, properties.openbao(), properties.authenticator(), json);
    }

    @Bean
    AuthenticatorService authenticatorService(JdbcClient jdbc, AuthenticatorSeedStore seeds, AuditLog audit, Clock clock,
            PlatformTransactionManager transactions, BrokerProperties properties) {
        return AuthenticatorService.create(jdbc, seeds, audit, clock, new TransactionTemplate(transactions),
                properties.authenticator());
    }

    @Bean
    AuthenticatorSweepJob authenticatorSweepJob(AuthenticatorService authenticator) {
        return new AuthenticatorSweepJob(authenticator);
    }

    @Bean
    CredentialService credentialService(SystemRegistry systems, ConnectionRepository connections, SecretStore secrets,
            InvalidationPublisher invalidations, OAuthService oauth, SubjectTokenVerifier subjectTokens, AuditLog audit,
            Clock clock, BrokerProperties properties, LostSecretSignal lostSecrets) {
        return new CredentialService(systems, connections, secrets, invalidations, oauth, subjectTokens, audit, clock,
                properties.cacheTtlSeconds(), properties.expiringThreshold(), lostSecrets);
    }

    @Bean
    OffboardingService offboardingService(ConnectionRepository connections, SecretStore secrets,
            InvalidationPublisher invalidations, OAuthService oauth, OAuthFlowStore flows, AuthenticatorService authenticator,
            AuditLog audit, Clock clock, BrokerProperties properties) {
        requireMarkerCoversFlows(properties.retention().purgeMarkerTtl(), properties.oauthFlow().flowTtl());
        return new OffboardingService(connections, secrets, invalidations, oauth, flows, authenticator, audit, clock,
                properties.retention());
    }

    /** A flow started just before a purge can be completed until its TTL ends; the marker must outlive it or the user could be written back. */
    static void requireMarkerCoversFlows(java.time.Duration markerTtl, java.time.Duration flowTtl) {
        if (markerTtl.compareTo(flowTtl) < 0) {
            throw new IllegalStateException("broker.retention.purge-marker-ttl (" + markerTtl
                    + ") must not be shorter than broker.oauth-flow.flow-ttl (" + flowTtl + ")");
        }
    }

    @Bean
    UnusedConnectionCleanupJob unusedConnectionCleanupJob(OffboardingService offboarding) {
        return new UnusedConnectionCleanupJob(offboarding);
    }

    /** redirect_uri registered at the providers: the BFF callback (C12) on the portal's public address. */
    static URI portalCallback(BrokerProperties properties) {
        String base = properties.portalBaseUrl().toString();
        return URI.create((base.endsWith("/") ? base.substring(0, base.length() - 1) : base) + "/api/v1/oauth/callback");
    }

    /**
     * Credentials and keys travel over these connections (PATs to whoami, AppRole secret to OpenBao, token
     * keys from JWKS), so plain HTTP is refused unless broker.allow-plain-http is set for a local stack.
     */
    static void requireTls(URI uri, String property, boolean allowPlainHttp) {
        if (uri == null) {
            return;
        }
        String scheme = uri.getScheme();
        if ("https".equals(scheme) || ("http".equals(scheme) && allowPlainHttp)) {
            return;
        }
        throw new IllegalStateException(property + " must use https (set broker.allow-plain-http=true only for local development)");
    }

    /**
     * Client for internal endpoints: trusts the internal CA of the SSL bundle, presents no client
     * certificate (the broker certificate is serverAuth only) and never follows redirects, which could
     * carry a credential to another host.
     */
    private static HttpClient internalClient(SslBundles sslBundles) {
        return HttpClient.newBuilder()
                .sslContext(trustOnly(sslBundles))
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    private static SSLContext trustOnly(SslBundles sslBundles) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, sslBundles.getBundle(SSL_BUNDLE).getManagers().getTrustManagers(), null);
            return context;
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("cannot build TLS client context", e);
        }
    }
}
