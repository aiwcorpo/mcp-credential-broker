package pl.aiwcorpo.mcp.broker.auth;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;

import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.KeySourceException;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;

/**
 * Token of the portal BFF (C4): issued by the IdP through token exchange, aud contains the broker, azp is
 * the BFF client. The azp check stops a token exchanged by another client (e.g. the gateway) from being
 * replayed with the BFF certificate.
 */
public class BffTokenVerifier {

    private final JwtDecoder decoder;
    private final String usernameClaim;

    public BffTokenVerifier(JwtDecoder decoder, String usernameClaim) {
        this.decoder = decoder;
        this.usernameClaim = usernameClaim;
    }

    public static BffTokenVerifier create(BrokerProperties.BffToken config, HttpClient http) {
        JdkClientHttpRequestFactory requests = new JdkClientHttpRequestFactory(http);
        requests.setReadTimeout(Duration.ofSeconds(5));
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(config.jwksUri().toString())
                .restOperations(new RestTemplate(requests))
                .build();
        decoder.setJwtValidator(validator(config));
        return new BffTokenVerifier(decoder, config.usernameClaim());
    }

    public static OAuth2TokenValidator<Jwt> validator(BrokerProperties.BffToken config) {
        OAuth2TokenValidator<Jwt> audience = jwt -> check(jwt.getAudience() != null
                && jwt.getAudience().contains(config.audience()), "aud");
        OAuth2TokenValidator<Jwt> authorizedParty = jwt -> check(config.allowedAzp().contains(jwt.getClaimAsString("azp")), "azp");
        OAuth2TokenValidator<Jwt> subject = jwt -> check(jwt.getSubject() != null && !jwt.getSubject().isBlank()
                && !jwt.getSubject().startsWith("system:") && jwt.getSubject().length() <= 255, "sub");
        return JwtValidators.createDefaultWithValidators(List.of(
                new JwtIssuerValidator(config.issuer()), audience, authorizedParty, subject));
    }

    private static OAuth2TokenValidatorResult check(boolean ok, String claim) {
        return ok ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "claim " + claim + " rejected", null));
    }

    private static boolean keySourceFailure(Throwable e) {
        for (Throwable cause = e; cause != null; cause = cause.getCause()) {
            if (cause instanceof KeySourceException) {
                return true;
            }
        }
        return false;
    }

    public Caller.PortalUser verify(String token, String requestId) {
        if (token == null || token.isEmpty()) {
            throw new TokenRejectedException("missing_token");
        }
        Jwt jwt;
        try {
            jwt = decoder.decode(token);
        } catch (JwtException e) {
            if (keySourceFailure(e)) {
                throw new KeySourceUnavailableException("IdP JWKS unavailable");
            }
            throw new TokenRejectedException("invalid_bff_token");
        }
        String username = jwt.getClaimAsString(usernameClaim);
        if (username == null || username.isBlank()) {
            throw new TokenRejectedException("invalid_bff_token");
        }
        return new Caller.PortalUser(requestId, jwt.getSubject(), username, jwt.getClaimAsString("azp"), jwt.getClaims());
    }
}
