package pl.aiwcorpo.mcp.broker.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.UncheckedIOException;
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

import pl.aiwcorpo.mcp.broker.support.Contracts;
import tools.jackson.databind.JsonNode;

/**
 * All C2 vectors of mcp-contracts 1.1.0 through the broker's verifier. Vectors addressed to an MCP server
 * (aud mcp-jira) are run with that audience: the verifier is the same code, and the server-only rule
 * (tool == params.name for tools/call) is applied here on top, as a server would.
 */
class InternalJwtVectorTest {

    static Stream<Arguments> vectors() {
        List<Resource> files = Contracts.vectors("jwt");
        assertThat(files).hasSizeGreaterThanOrEqualTo(38);
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
        InternalJwtVerifier subject = verifier(verifier, replay, false);

        String token = vector.path("token").isString() ? vector.path("token").stringValue() : null;
        boolean jsonRpc = "jsonrpc".equals(request.path("kind").stringValue());
        String method = request.path("method").stringValue();
        boolean serviceAllowed = jsonRpc ? !"tools/call".equals(method)
                : "/v1/systems".equals(request.path("path").stringValue()) || "/mcp-manifest".equals(request.path("path").stringValue());
        String xRequestId = request.path("xRequestId").asString(null);

        String reason;
        try {
            InternalJwtClaims claims = subject.verify(token, xRequestId, serviceAllowed);
            boolean toolMismatch = jsonRpc && "tools/call".equals(method)
                    && !request.path("toolName").stringValue().equals(claims.tool());
            reason = toolMismatch ? "tool_mismatch" : null;
        } catch (TokenRejectedException e) {
            reason = e.reason();
        }
        String expectedReason = expected.path("valid").asBoolean() ? null : expected.path("reason").stringValue();
        assertThat(reason).as(name).isEqualTo(expectedReason);
    }

    @Test
    void productionRejectsPublishedTestKids() {
        JsonNode vector = Contracts.json("test-vectors/jwt/valid-broker.json");
        InternalJwtVerifier production = verifier(vector.path("verifier"), new InMemoryReplayGuard(), true);
        assertThatThrownBy(() -> production.verify(vector.path("token").stringValue(),
                vector.path("request").path("xRequestId").stringValue(), false))
                .isInstanceOf(TokenRejectedException.class)
                .extracting(e -> ((TokenRejectedException) e).reason()).isEqualTo("test_kid_not_allowed");
    }

    @Test
    void brokerVectorsCoverResolveAndSystems() {
        JsonNode valid = Contracts.json("test-vectors/jwt/valid-broker.json");
        InternalJwtClaims claims = verifier(valid.path("verifier"), new InMemoryReplayGuard(), false)
                .verify(valid.path("token").stringValue(), valid.path("request").path("xRequestId").stringValue(), false);
        assertThat(claims.service()).isFalse();
        assertThat(claims.sub()).isEqualTo(valid.path("claims").path("sub").stringValue());

        JsonNode service = Contracts.json("test-vectors/jwt/valid-service-broker-systems.json");
        InternalJwtClaims serviceClaims = verifier(service.path("verifier"), new InMemoryReplayGuard(), false)
                .verify(service.path("token").stringValue(), service.path("request").path("xRequestId").stringValue(), true);
        assertThat(serviceClaims.service()).isTrue();
    }

    @Test
    void replayedJtiIsRejectedOnSecondUse() {
        JsonNode vector = Contracts.json("test-vectors/jwt/valid-broker.json");
        InternalJwtVerifier subject = verifier(vector.path("verifier"), new InMemoryReplayGuard(), false);
        String token = vector.path("token").stringValue();
        String rid = vector.path("request").path("xRequestId").stringValue();
        subject.verify(token, rid, false);
        assertThatThrownBy(() -> subject.verify(token, rid, false))
                .extracting(e -> ((TokenRejectedException) e).reason()).isEqualTo("replayed_jti");
    }

    private static InternalJwtVerifier verifier(JsonNode verifier, ReplayGuard replay, boolean rejectTestKids) {
        Clock clock = Clock.fixed(Instant.parse(verifier.path("now").stringValue()), ZoneOffset.UTC);
        String jwks = Contracts.text("test-vectors/" + verifier.path("jwks").stringValue());
        GatewayKeys keys = new JwksGatewayKeys(() -> jwks, "vectors", clock, Duration.ofDays(1), Duration.ZERO, Duration.ofDays(1));
        return new InternalJwtVerifier(verifier.path("issuer").stringValue(), verifier.path("audience").stringValue(),
                keys, replay, clock, Duration.ofSeconds(verifier.path("clockSkewSeconds").asLong()),
                Duration.ofSeconds(verifier.path("maxLifetimeSeconds").asLong()), rejectTestKids);
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
