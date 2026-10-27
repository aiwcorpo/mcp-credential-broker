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
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.BffTokenVerifier;
import pl.aiwcorpo.mcp.broker.auth.CallerAuthenticationFilter;
import pl.aiwcorpo.mcp.broker.auth.GatewayKeys;
import pl.aiwcorpo.mcp.broker.auth.InternalJwtVerifier;
import pl.aiwcorpo.mcp.broker.auth.JwksGatewayKeys;
import pl.aiwcorpo.mcp.broker.auth.RedisReplayGuard;
import pl.aiwcorpo.mcp.broker.auth.ReplayGuard;
import pl.aiwcorpo.mcp.broker.credential.ConnectionRepository;
import pl.aiwcorpo.mcp.broker.credential.CredentialService;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.event.RedisInvalidationPublisher;
import pl.aiwcorpo.mcp.broker.secret.OpenBaoClient;
import pl.aiwcorpo.mcp.broker.secret.OpenBaoSecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import tools.jackson.databind.json.JsonMapper;

@Configuration(proxyBeanMethods = false)
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
        return JwksGatewayKeys.fromUri(config.jwksUri(), internalClient(sslBundles), Duration.ofSeconds(5), clock,
                config.jwksRefresh(), config.jwksMinRefreshInterval(), config.jwksMaxStale());
    }

    @Bean
    ReplayGuard replayGuard(StringRedisTemplate redis, BrokerProperties properties) {
        return new RedisReplayGuard(redis, properties.redis().jtiPrefix());
    }

    @Bean
    InternalJwtVerifier internalJwtVerifier(BrokerProperties properties, GatewayKeys keys, ReplayGuard replayGuard, Clock clock) {
        BrokerProperties.GatewayJwt config = properties.gatewayJwt();
        return new InternalJwtVerifier(config.issuer(), config.audience(), keys, replayGuard, clock,
                config.clockSkew(), config.maxLifetime(), config.allowTestKeys());
    }

    @Bean
    BffTokenVerifier bffTokenVerifier(BrokerProperties properties, SslBundles sslBundles) {
        requireTls(properties.bffToken().jwksUri(), "broker.bff-token.jwks-uri", properties.allowPlainHttp());
        return BffTokenVerifier.create(properties.bffToken(), internalClient(sslBundles));
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
    SecretStore secretStore(BrokerProperties properties, SslBundles sslBundles, JsonMapper json, Clock clock) {
        BrokerProperties.OpenBao config = properties.openbao();
        requireTls(config.address(), "broker.openbao.address", properties.allowPlainHttp());
        return new OpenBaoSecretStore(new OpenBaoClient(config, internalClient(sslBundles), json, clock), config, json);
    }

    @Bean
    SystemRegistry systemRegistry(BrokerProperties properties, SslBundles sslBundles, JsonMapper json) {
        properties.systems().forEach((id, system) ->
                requireTls(system.baseUrl(), "broker.systems." + id + ".base-url", properties.allowPlainHttp()));
        return new SystemRegistry(properties.systems(), internalClient(sslBundles), json);
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
    CredentialService credentialService(SystemRegistry systems, ConnectionRepository connections, SecretStore secrets,
            InvalidationPublisher invalidations, AuditLog audit, Clock clock, BrokerProperties properties) {
        return new CredentialService(systems, connections, secrets, invalidations, audit, clock,
                properties.cacheTtlSeconds(), properties.expiringThreshold());
    }

    /**
     * Credentials and keys travel over these connections (PATs to whoami, AppRole secret to OpenBao, token
     * keys from JWKS), so plain HTTP is refused unless broker.allow-plain-http is set for a local stack.
     */
    static void requireTls(URI uri, String property, boolean allowPlainHttp) {
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
