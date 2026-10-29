package pl.aiwcorpo.mcp.broker.auth;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;

import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.KeySourceException;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;

/**
 * The {@code subjectToken} of a token-exchange resolve (C4, CC-157): the user's token that the gateway exchanged for
 * aud mcp-credential-broker. It is checked the way the token of the BFF is (signature and issuer against the key set
 * of the IdP, audience, expiry with the clock skew of C2) and its {@code sub} must be the one of the internal JWT of
 * the call, so that a mistake of the gateway cannot turn the token of one user into a credential for another.
 * Reading the claims without checking them would not be a check. The client that obtained the token (azp) is not
 * restricted: that is the IdP's decision when it issues the exchange.
 */
public class SubjectTokenVerifier {

    private final JwtDecoder decoder;

    public SubjectTokenVerifier(JwtDecoder decoder) {
        this.decoder = decoder;
    }

    public static SubjectTokenVerifier create(BrokerProperties.BffToken idp, Duration clockSkew, HttpClient http) {
        JdkClientHttpRequestFactory requests = new JdkClientHttpRequestFactory(http);
        requests.setReadTimeout(Duration.ofSeconds(5));
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(idp.jwksUri().toString())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .restOperations(new RestTemplate(requests))
                .build();
        OAuth2TokenValidator<Jwt> audience = jwt -> jwt.getAudience() != null && jwt.getAudience().contains(idp.audience())
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "aud", null));
        JwtTimestampValidator timestamps = new JwtTimestampValidator(clockSkew);
        timestamps.setAllowEmptyExpiryClaim(false);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(List.of(
                timestamps, new JwtIssuerValidator(idp.issuer()), audience)));
        return new SubjectTokenVerifier(decoder);
    }

    /**
     * @throws TokenRejectedException when the token fails a check or belongs to another user
     * @throws KeySourceUnavailableException when the key set of the IdP cannot be read
     */
    public void verify(String token, String expectedSub) {
        Jwt jwt;
        try {
            jwt = decoder.decode(token);
        } catch (JwtException e) {
            for (Throwable cause = e; cause != null; cause = cause.getCause()) {
                if (cause instanceof KeySourceException) {
                    throw new KeySourceUnavailableException("IdP JWKS unavailable");
                }
            }
            throw new TokenRejectedException("invalid_subject_token");
        }
        if (jwt.getSubject() == null || !jwt.getSubject().equals(expectedSub)) {
            throw new TokenRejectedException("subject_token_sub_mismatch");
        }
    }
}
