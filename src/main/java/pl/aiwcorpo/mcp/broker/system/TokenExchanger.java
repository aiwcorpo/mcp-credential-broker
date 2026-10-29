package pl.aiwcorpo.mcp.broker.system;

import java.time.Instant;
import java.util.Objects;

import pl.aiwcorpo.mcp.broker.secret.SecretValue;

/** RFC 8693 token exchange of one target system in the IdP (C4.2 token-exchange). */
public interface TokenExchanger {

    /** The token for the system. {@code expiresAt} is always set: the contract has no token-exchange without an expiry. */
    record ExchangedToken(SecretValue accessToken, Instant expiresAt) {

        public ExchangedToken {
            Objects.requireNonNull(accessToken, "accessToken");
            Objects.requireNonNull(expiresAt, "expiresAt");
        }

        @Override
        public String toString() {
            return "ExchangedToken[expiresAt=" + expiresAt + "]";
        }
    }

    /**
     * Throws {@link ExchangeDeniedException} when the IdP refuses to issue the token for this user and
     * {@link UpstreamUnavailableException} for everything else that goes wrong, the broker's own client credentials included.
     */
    ExchangedToken exchange(SecretValue subjectToken);
}
