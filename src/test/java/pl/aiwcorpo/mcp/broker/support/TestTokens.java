package pl.aiwcorpo.mcp.broker.support;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import pl.aiwcorpo.mcp.broker.auth.RequestIds;

/**
 * Tokens for the integration tests: the gateway's internal JWT signed with the published test key A of
 * mcp-contracts (kid test-gw-2026-10-a), and IdP tokens of the portal BFF signed with a key generated here.
 */
public final class TestTokens {

    public static final String GATEWAY_ISSUER = "https://mcp-gateway.internal";
    public static final String IDP_ISSUER = "http://idp.test/realms/corp";
    public static final String GATEWAY_JWKS_PATH = "test-vectors/keys/test-gateway-jwks.json";

    private final ECKey gatewayKey;
    private final RSAKey idpKey;

    public TestTokens() {
        try {
            gatewayKey = ECKey.parse(Contracts.text("test-vectors/keys/test-gateway-jwt-a.NOT-FOR-PRODUCTION.private.jwk.json"));
            idpKey = new RSAKeyGenerator(2048).keyID("test-idp-it").generate();
        } catch (ParseException | JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public String idpJwks() {
        return new JWKSet(idpKey.toPublicJWK()).toString();
    }

    public static String newRequestId() {
        return RequestIds.next(Clock.systemUTC());
    }

    /** User variant of C2 with aud=mcp-credential-broker, as the gateway sends it for resolve. */
    public String gatewayUser(String sub, String username, String requestId) {
        return gatewayUser(sub, username, requestId, "get_issue");
    }

    /** User variant with the given {@code tool}; null leaves the claim out (CC-038). */
    public String gatewayUser(String sub, String username, String requestId, String tool) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(GATEWAY_ISSUER)
                .claim("aud", "mcp-credential-broker")
                .subject(sub)
                .claim("usr", username)
                .claim("grp", List.of("mcp-jira-read"))
                .claim("azp", "claude-code")
                .claim("rid", requestId)
                .claim("prv", "20261026120000-a1b2c3d")
                .claim("iat", now.getEpochSecond())
                .claim("exp", now.getEpochSecond() + 60)
                .jwtID(UUID.randomUUID().toString());
        if (tool != null) {
            claims.claim("tool", tool);
        }
        return signGateway(claims.build());
    }

    /** Service variant (CC-030), accepted only for GET /v1/systems. */
    public String gatewayService(String requestId) {
        Instant now = Instant.now();
        return signGateway(new JWTClaimsSet.Builder()
                .issuer(GATEWAY_ISSUER)
                .claim("aud", "mcp-credential-broker")
                .subject("system:mcp-gateway")
                .claim("grp", List.of())
                .claim("rid", requestId)
                .claim("prv", "20261026120000-a1b2c3d")
                .claim("iat", now.getEpochSecond())
                .claim("exp", now.getEpochSecond() + 60)
                .jwtID(UUID.randomUUID().toString())
                .build());
    }

    /** Token the BFF gets from token exchange: aud contains the broker, azp is the BFF client. */
    public String bffUser(String sub, String username) {
        return bff(sub, username, "mcp-portal-bff", "mcp-credential-broker");
    }

    public String bff(String sub, String username, String azp, String audience) {
        return idpToken(IDP_ISSUER, sub, username, azp, audience, Instant.now().plusSeconds(300));
    }

    /** What the gateway passes as subjectToken: the user's token exchanged for aud=mcp-credential-broker. */
    public String subjectToken(String sub, String username) {
        return idpToken(IDP_ISSUER, sub, username, "mcp-gateway", "mcp-credential-broker", Instant.now().plusSeconds(300));
    }

    /** A token of the IdP key with every claim under the test's control. */
    public String idpToken(String issuer, String sub, String username, String azp, String audience, Instant expiresAt) {
        return idpToken(issuer, sub, username, azp, audience, expiresAt, JOSEObjectType.JWT);
    }

    /** Same, with the header type (typ) chosen by the test. */
    public String idpToken(String issuer, String sub, String username, String azp, String audience, Instant expiresAt,
            JOSEObjectType type) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(sub)
                .audience(List.of(audience))
                .claim("azp", azp)
                .claim("preferred_username", username)
                .claim("email", username + "@corp.test")
                .issueTime(Date.from(now.minusSeconds(3600)))
                .expirationTime(expiresAt == null ? null : Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString())
                .build();
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(idpKey.getKeyID())
                    .type(type).build(), claims);
            jwt.sign(new RSASSASigner(idpKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Claims of a valid subject token under an unsecured header (alg none): the signature part is empty. */
    public String unsecuredSubjectToken(String sub) {
        return new com.nimbusds.jwt.PlainJWT(subjectClaims(sub)).serialize();
    }

    /** The same claims signed with HMAC (HS256) under a key the attacker chose. */
    public String hmacSubjectToken(String sub) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(idpKey.getKeyID()).build(), subjectClaims(sub));
            jwt.sign(new com.nimbusds.jose.crypto.MACSigner("0123456789abcdef0123456789abcdef"));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static JWTClaimsSet subjectClaims(String sub) {
        return new JWTClaimsSet.Builder().issuer(IDP_ISSUER).subject(sub).audience(List.of("mcp-credential-broker"))
                .claim("azp", "mcp-gateway").expirationTime(Date.from(Instant.now().plusSeconds(300))).build();
    }

    private String signGateway(JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(gatewayKey.getKeyID())
                    .type(JOSEObjectType.JWT).build(), claims);
            jwt.sign(new ECDSASigner(gatewayKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }
}
