package pl.aiwcorpo.mcp.broker.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import pl.aiwcorpo.mcp.broker.auth.InternalJwtVerifier.ToolClaim;
import pl.aiwcorpo.mcp.broker.support.Contracts;

/** The claims resource, pty and act of CC-260 as the broker receives them, with tokens signed by the published test key. */
class InternalJwtPrincipalClaimsTest {

    private static final Instant ISSUED = Instant.parse("2026-10-27T12:00:00Z");
    private static final String RID = "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f";
    private static final String URI = "servicedesk://ticket/SD-1042";

    private final Set<String> seen = new HashSet<>();
    private int counter;

    @Test
    void aResolveTokenWithAResourceAndNoToolIsAccepted() {
        InternalJwtClaims claims = verify(claims("resource", URI), ToolClaim.TOOL_OR_RESOURCE);

        assertThat(claims.resource()).isEqualTo(URI);
        assertThat(claims.tool()).isNull();
        assertThat(claims.pty()).isNull();
    }

    @Test
    void aTokenWithBothToolAndResourceIsInvalidClaims() {
        assertThat(reasonOf(claims("tool", "get_issue", "resource", URI), ToolClaim.TOOL_OR_RESOURCE)).isEqualTo("invalid_claims");
    }

    @Test
    void aResolveTokenWithNeitherToolNorResourceIsRefused() {
        assertThat(reasonOf(claims(), ToolClaim.TOOL_OR_RESOURCE)).isEqualTo("tool_missing");
    }

    @Test
    void aResourceIsRefusedWhereOnlyAToolOrNothingIsAllowed() {
        assertThat(reasonOf(claims("resource", URI), ToolClaim.REQUIRED)).isEqualTo("resource_not_allowed");
        assertThat(reasonOf(claims("resource", URI), ToolClaim.FORBIDDEN)).isEqualTo("resource_not_allowed");
    }

    @Test
    void aResourceThatIsNotAResourceUriIsInvalidClaims() {
        for (String value : List.of("not-a-uri", "Servicedesk://ticket/1", "servicedesk://", "servicedesk://ticket/a b",
                "servicedesk://" + "x".repeat(2001))) {
            assertThat(reasonOf(claims("resource", value), ToolClaim.TOOL_OR_RESOURCE)).as(value).isEqualTo("invalid_claims");
        }
        assertThat(reasonOf(claims("resource", 5), ToolClaim.TOOL_OR_RESOURCE)).isEqualTo("invalid_claims");
    }

    @Test
    void anAgentTokenWithoutActIsAcceptedAndKnownAsAnAgent() {
        InternalJwtClaims claims = verify(claims("pty", "agent", "tool", "get_issue"), ToolClaim.REQUIRED);

        assertThat(claims.isAgent()).isTrue();
        assertThat(claims.act()).isNull();
    }

    @Test
    void aDelegatedTokenWithActIsAcceptedAndKeepsTheHumanSub() {
        InternalJwtClaims claims = verify(claims("pty", "delegated", "tool", "get_issue",
                "act", Map.of("sub", "agent-sub", "azp", "agent-triage")), ToolClaim.REQUIRED);

        assertThat(claims.sub()).isEqualTo("alice-sub");
        assertThat(claims.isAgent()).isFalse();
        assertThat(claims.act()).isEqualTo(new InternalJwtClaims.Actor("agent-sub", "agent-triage"));
    }

    @Test
    void aDelegatedTokenWithoutActIsInvalidClaims() {
        assertThat(reasonOf(claims("pty", "delegated", "tool", "get_issue"), ToolClaim.REQUIRED)).isEqualTo("invalid_claims");
    }

    @Test
    void anAgentTokenWithActIsInvalidClaims() {
        assertThat(reasonOf(claims("pty", "agent", "tool", "get_issue", "act", Map.of("sub", "a", "azp", "b")), ToolClaim.REQUIRED))
                .isEqualTo("invalid_claims");
    }

    @Test
    void actWithoutPtyIsInvalidClaims() {
        assertThat(reasonOf(claims("tool", "get_issue", "act", Map.of("sub", "a", "azp", "b")), ToolClaim.REQUIRED))
                .isEqualTo("invalid_claims");
    }

    @Test
    void actWithAnExtraFieldOrAMissingOneIsInvalidClaims() {
        assertThat(reasonOf(claims("pty", "delegated", "tool", "get_issue", "act", Map.of("sub", "a", "azp", "b", "x", "c")),
                ToolClaim.REQUIRED)).isEqualTo("invalid_claims");
        assertThat(reasonOf(claims("pty", "delegated", "tool", "get_issue", "act", Map.of("sub", "a")), ToolClaim.REQUIRED))
                .isEqualTo("invalid_claims");
        assertThat(reasonOf(claims("pty", "delegated", "tool", "get_issue", "act", Map.of("sub", "", "azp", "b")), ToolClaim.REQUIRED))
                .isEqualTo("invalid_claims");
    }

    @Test
    void ptyUserOrAnyOtherValueIsInvalidClaims() {
        for (Object value : List.of("user", "human", "", 1)) {
            assertThat(reasonOf(claims("pty", value, "tool", "get_issue"), ToolClaim.REQUIRED)).as(String.valueOf(value))
                    .isEqualTo("invalid_claims");
        }
    }

    @Test
    void theServiceVariantStillRefusesTheNewClaims() {
        Map<String, Object> service = new LinkedHashMap<>(Map.of("iss", "https://mcp-gateway.internal", "aud", "mcp-credential-broker",
                "use", "call", "sub", InternalJwtClaims.SERVICE_SUB, "grp", List.of(), "rid", RID, "prv", 7L,
                "iat", ISSUED.getEpochSecond(), "exp", ISSUED.getEpochSecond() + 60, "jti", "j-service"));
        service.put("resource", URI);
        assertThat(reasonOf(service, ToolClaim.FORBIDDEN, true)).isEqualTo("invalid_claims");
    }

    private Map<String, Object> claims(Object... extra) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", "https://mcp-gateway.internal");
        claims.put("aud", "mcp-credential-broker");
        claims.put("use", "call");
        claims.put("sub", "alice-sub");
        claims.put("usr", "alice");
        claims.put("grp", List.of());
        claims.put("azp", "claude-code");
        claims.put("rid", RID);
        claims.put("prv", 7L);
        claims.put("iat", ISSUED.getEpochSecond());
        claims.put("exp", ISSUED.getEpochSecond() + 60);
        claims.put("jti", "j-" + counter++);
        for (int i = 0; i < extra.length; i += 2) {
            claims.put((String) extra[i], extra[i + 1]);
        }
        return claims;
    }

    private InternalJwtClaims verify(Map<String, Object> claims, ToolClaim rule) {
        return verifier().verify(sign(claims), RID, false, rule);
    }

    private String reasonOf(Map<String, Object> claims, ToolClaim rule) {
        return reasonOf(claims, rule, false);
    }

    private String reasonOf(Map<String, Object> claims, ToolClaim rule, boolean serviceAllowed) {
        InternalJwtVerifier verifier = verifier();
        String token = sign(claims);
        return assertThatThrownBy(() -> verifier.verify(token, RID, serviceAllowed, rule))
                .isInstanceOf(TokenRejectedException.class)
                .actual() instanceof TokenRejectedException e ? e.reason() : null;
    }

    private InternalJwtVerifier verifier() {
        Clock clock = Clock.fixed(ISSUED.plusSeconds(5), ZoneOffset.UTC);
        try {
            ECKey key = ECKey.parse(Contracts.text("test-vectors/keys/test-gateway-jwt-a.NOT-FOR-PRODUCTION.private.jwk.json"));
            String jwks = new JWKSet(key.toPublicJWK()).toString();
            GatewayKeys keys = new JwksGatewayKeys(() -> jwks, "claims", clock, Duration.ofDays(1), Duration.ZERO, Duration.ofDays(1));
            return new InternalJwtVerifier("https://mcp-gateway.internal", "mcp-credential-broker", keys,
                    (jti, ttl) -> seen.add(jti), clock, Duration.ofSeconds(30), Duration.ofSeconds(60), true);
        } catch (java.text.ParseException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String sign(Map<String, Object> claims) {
        try {
            ECKey key = ECKey.parse(Contracts.text("test-vectors/keys/test-gateway-jwt-a.NOT-FOR-PRODUCTION.private.jwk.json"));
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
            claims.forEach(builder::claim);
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(), builder.build());
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
