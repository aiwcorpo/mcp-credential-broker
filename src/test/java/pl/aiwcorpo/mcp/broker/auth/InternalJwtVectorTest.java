package pl.aiwcorpo.mcp.broker.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.io.Resource;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import pl.aiwcorpo.mcp.broker.auth.InternalJwtVerifier.ToolClaim;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import tools.jackson.databind.JsonNode;

/**
 * All C2 vectors of mcp-contracts 2.0.0 through the broker's verifier, compared on result and reason.
 * Vectors addressed to an MCP server (aud mcp-jira) run with that audience and the server's per-method
 * rules (CC-038): tools/call needs tool == params.name, protocol methods must not carry tool, and only
 * protocol methods accept the service variant. The broker's own operations use the rules of {@link Operation}.
 */
class InternalJwtVectorTest {

    private static final Set<String> PROTOCOL_METHODS = Set.of("initialize", "server/discover", "tools/list", "ping");

    static Stream<Arguments> vectors() {
        List<Resource> files = Contracts.vectors("jwt");
        assertThat(files).hasSizeGreaterThanOrEqualTo(43);
        return files.stream().map(file -> Arguments.of(file.getFilename(), read(file)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void vector(String name, JsonNode vector) {
        JsonNode verifier = vector.path("verifier");
        JsonNode request = vector.path("request");
        JsonNode expected = vector.path("expected");

        InMemoryReplayGuard replay = new InMemoryReplayGuard();
        verifier.path("seenJtis").forEach(jti -> replay.seen.add(jti.stringValue()));
        InternalJwtVerifier subject = verifier(verifier, replay, verifier.path("allowTestKeys").asBoolean(false),
                verifier.path("devstackProfile").asBoolean(false));

        String token = vector.path("token").isString() ? vector.path("token").stringValue() : null;
        boolean jsonRpc = "jsonrpc".equals(request.path("kind").stringValue());
        String method = request.path("method").stringValue();
        boolean toolsCall = jsonRpc && "tools/call".equals(method);
        boolean serviceAllowed;
        ToolClaim toolClaim;
        if (jsonRpc) {
            serviceAllowed = PROTOCOL_METHODS.contains(method);
            toolClaim = toolsCall ? ToolClaim.REQUIRED : ToolClaim.FORBIDDEN;
        } else if ("/mcp-manifest".equals(request.path("path").stringValue())) {
            serviceAllowed = true;
            toolClaim = ToolClaim.FORBIDDEN;
        } else {
            Operation operation = Operation.match(method, request.path("path").stringValue()).orElseThrow();
            serviceAllowed = operation.serviceVariantAllowed();
            toolClaim = operation.toolClaim();
        }
        String xRequestId = request.path("xRequestId").asString(null);

        String reason;
        try {
            InternalJwtClaims claims = subject.verify(token, xRequestId, serviceAllowed, toolClaim);
            reason = toolsCall && !request.path("toolName").stringValue().equals(claims.tool()) ? "tool_mismatch" : null;
        } catch (TokenRejectedException e) {
            reason = e.reason();
        }
        String expectedReason = expected.path("valid").asBoolean() ? null : expected.path("reason").stringValue();
        if ("adapter".equals(verifier.path("receiverMode").asString(null))) {
            // The sidecar of an adapter is the only receiver of mcp_risk and mcp_action; the broker refuses them (CC-226).
            if (!expected.path("valid").asBoolean()) {
                return;
            }
            expectedReason = "invalid_claims";
        }
        assertThat(reason).as(name).isEqualTo(expectedReason);
    }

    @Test
    void publishedTestKeysAreRefusedByKidAndBySpki() throws ParseException {
        JsonNode vector = Contracts.json("test-vectors/jwt/valid-broker.json");
        InternalJwtVerifier production = verifier(vector.path("verifier"), new InMemoryReplayGuard(), false);
        assertThatThrownBy(() -> production.verify(vector.path("token").stringValue(),
                vector.path("request").path("xRequestId").stringValue(), false, ToolClaim.REQUIRED))
                .extracting(e -> ((TokenRejectedException) e).reason()).isEqualTo("test_key_not_allowed");

        Set<String> published = new HashSet<>();
        for (String file : List.of("test-gateway-jwt-a", "test-gateway-jwt-b", "test-attacker-jwt", "test-idp-corp")) {
            ECKey key = JWK.parse(Contracts.text("test-vectors/keys/" + file + ".public.jwk.json")).toECKey();
            ECKey renamed = new ECKey.Builder(key).keyID("prod-2026-10").build();
            assertThat(InternalJwtVerifier.isPublishedTestKey(renamed)).as(file).isTrue();
            published.add(file);
        }
        assertThat(InternalJwtVerifier.TEST_KEY_SPKI_SHA256).hasSameSizeAs(published);
        for (JWK key : JWKSet.parse(Contracts.text("test-vectors/keys/test-gateway-jwks.json")).getKeys()) {
            assertThat(InternalJwtVerifier.isPublishedTestKey(key.toECKey())).isTrue();
        }
    }

    @Test
    void testKeyUnderAProductionKidIsRefused() throws Exception {
        ECKey testKey = ECKey.parse(Contracts.text("test-vectors/keys/test-gateway-jwt-a.NOT-FOR-PRODUCTION.private.jwk.json"));
        ECKey renamed = new ECKey.Builder(testKey).keyID("prod-2026-10").build();
        Instant now = Instant.parse("2026-10-27T12:00:00Z");
        String rid = "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f";
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://mcp-gateway.internal").claim("aud", "mcp-credential-broker").subject("u-1")
                .claim("usr", "alice").claim("grp", List.of()).claim("azp", "claude-code").claim("tool", "get_issue")
                .claim("rid", rid).claim("prv", "20261026120000-a1b2c3d")
                .claim("iat", now.getEpochSecond()).claim("exp", now.getEpochSecond() + 60).jwtID("j-1").build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(renamed.getKeyID()).build(), claims);
        jwt.sign(new ECDSASigner(renamed));

        Clock clock = Clock.fixed(now.plusSeconds(5), ZoneOffset.UTC);
        String jwks = new JWKSet(renamed.toPublicJWK()).toString();
        GatewayKeys keys = new JwksGatewayKeys(() -> jwks, "renamed", clock, Duration.ofDays(1), Duration.ZERO, Duration.ofDays(1));
        InternalJwtVerifier production = new InternalJwtVerifier("https://mcp-gateway.internal", "mcp-credential-broker",
                keys, new InMemoryReplayGuard(), clock, Duration.ofSeconds(30), Duration.ofSeconds(60), false);
        assertThatThrownBy(() -> production.verify(jwt.serialize(), rid, false, ToolClaim.REQUIRED))
                .extracting(e -> ((TokenRejectedException) e).reason()).isEqualTo("test_key_not_allowed");

        InternalJwtVerifier dev = new InternalJwtVerifier("https://mcp-gateway.internal", "mcp-credential-broker",
                keys, new InMemoryReplayGuard(), clock, Duration.ofSeconds(30), Duration.ofSeconds(60), true);
        assertThat(dev.verify(jwt.serialize(), rid, false, ToolClaim.REQUIRED).sub()).isEqualTo("u-1");
    }

    @Test
    void brokerVectorsCoverResolveAndSystems() {
        JsonNode valid = Contracts.json("test-vectors/jwt/valid-broker.json");
        InternalJwtClaims claims = verifier(valid.path("verifier"), new InMemoryReplayGuard(), true)
                .verify(valid.path("token").stringValue(), valid.path("request").path("xRequestId").stringValue(),
                        false, ToolClaim.REQUIRED);
        assertThat(claims.service()).isFalse();
        assertThat(claims.tool()).isNotNull();

        JsonNode service = Contracts.json("test-vectors/jwt/valid-service-broker-systems.json");
        InternalJwtClaims serviceClaims = verifier(service.path("verifier"), new InMemoryReplayGuard(), true)
                .verify(service.path("token").stringValue(), service.path("request").path("xRequestId").stringValue(),
                        true, ToolClaim.FORBIDDEN);
        assertThat(serviceClaims.service()).isTrue();
    }

    @Test
    void replayedJtiIsRejectedOnSecondUse() {
        JsonNode vector = Contracts.json("test-vectors/jwt/valid-broker.json");
        InternalJwtVerifier subject = verifier(vector.path("verifier"), new InMemoryReplayGuard(), true);
        String token = vector.path("token").stringValue();
        String rid = vector.path("request").path("xRequestId").stringValue();
        subject.verify(token, rid, false, ToolClaim.REQUIRED);
        assertThatThrownBy(() -> subject.verify(token, rid, false, ToolClaim.REQUIRED))
                .extracting(e -> ((TokenRejectedException) e).reason()).isEqualTo("replayed_jti");
    }

    private static InternalJwtVerifier verifier(JsonNode verifier, ReplayGuard replay, boolean allowTestKeys) {
        return verifier(verifier, replay, allowTestKeys, allowTestKeys);
    }

    private static InternalJwtVerifier verifier(JsonNode verifier, ReplayGuard replay, boolean allowTestKeys,
            boolean devstackProfile) {
        Clock clock = Clock.fixed(Instant.parse(verifier.path("now").stringValue()), ZoneOffset.UTC);
        String jwks = Contracts.text("test-vectors/" + verifier.path("jwks").stringValue());
        GatewayKeys keys = new JwksGatewayKeys(() -> jwks, "vectors", clock, Duration.ofDays(1), Duration.ZERO, Duration.ofDays(1));
        return new InternalJwtVerifier(verifier.path("issuer").stringValue(), verifier.path("audience").stringValue(),
                keys, replay, clock, Duration.ofSeconds(verifier.path("clockSkewSeconds").asLong()),
                Duration.ofSeconds(verifier.path("maxLifetimeSeconds").asLong()), allowTestKeys, devstackProfile);
    }

    private static JsonNode read(Resource file) {
        try {
            return Contracts.JSON.readTree(file.getContentAsByteArray());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static final class InMemoryReplayGuard implements ReplayGuard {

        final Set<String> seen = new HashSet<>();

        @Override
        public boolean firstUse(String jti, Duration ttl) {
            return seen.add(jti);
        }
    }
}
