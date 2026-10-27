package pl.aiwcorpo.mcp.broker.config;

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
        HttpClient http = HttpClient.newBuilder()
                .sslContext(trustOnly(sslBundles))
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        return JwksGatewayKeys.fromUri(config.jwksUri(), http, Duration.ofSeconds(5), clock, config.jwksRefresh(),
                config.jwksMinRefreshInterval());
    }

    @Bean
    ReplayGuard replayGuard(StringRedisTemplate redis, BrokerProperties properties) {
        return new RedisReplayGuard(redis, properties.redis().jtiPrefix());
    }

    @Bean
    InternalJwtVerifier internalJwtVerifier(BrokerProperties properties, GatewayKeys keys, ReplayGuard replayGuard, Clock clock) {
        BrokerProperties.GatewayJwt config = properties.gatewayJwt();
        return new InternalJwtVerifier(config.issuer(), config.audience(), keys, replayGuard, clock,
                config.clockSkew(), config.maxLifetime(), config.rejectTestKids());
    }

    @Bean
    BffTokenVerifier bffTokenVerifier(BrokerProperties properties) {
        return BffTokenVerifier.create(properties.bffToken());
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
        HttpClient.Builder http = HttpClient.newBuilder()
                .connectTimeout(config.timeout())
                .followRedirects(HttpClient.Redirect.NEVER);
        if ("https".equals(config.address().getScheme())) {
            http.sslContext(trustOnly(sslBundles));
        }
        return new OpenBaoSecretStore(new OpenBaoClient(config, http.build(), json, clock), config, json);
    }

    @Bean
    SystemRegistry systemRegistry(BrokerProperties properties, JsonMapper json) {
        HttpClient whoami = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        return new SystemRegistry(properties.systems(), whoami, json);
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
