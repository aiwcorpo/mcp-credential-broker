package pl.aiwcorpo.mcp.broker.auth;

import java.time.Clock;
import java.time.Duration;

import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.TestTokens;

/** A verifier for tokens made by {@link TestTokens}, for tests outside this package; it accepts every jti once and again. */
public final class TestGatewayVerifier {

    private TestGatewayVerifier() {
    }

    public static InternalJwtVerifier create() {
        Clock clock = Clock.systemUTC();
        String jwks = Contracts.text(TestTokens.GATEWAY_JWKS_PATH);
        return new InternalJwtVerifier(TestTokens.GATEWAY_ISSUER, "mcp-credential-broker",
                new JwksGatewayKeys(() -> jwks, "test-gateway", clock, Duration.ofDays(1), Duration.ZERO, Duration.ofDays(1)),
                (jti, ttl) -> true, clock, Duration.ofSeconds(30), Duration.ofSeconds(60), true);
    }
}
