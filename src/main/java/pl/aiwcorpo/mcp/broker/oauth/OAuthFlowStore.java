package pl.aiwcorpo.mcp.broker.oauth;

import java.time.Duration;
import java.util.Optional;

import pl.aiwcorpo.mcp.broker.secret.SecretValue;

/**
 * Pending authorization flows. A flow ties a {@code state} and a PKCE verifier to the user ({@code sub}) who
 * started it; it lives for a few minutes and can be consumed once.
 */
public interface OAuthFlowStore {

    /** {@code clientRevision}: the revision of the system's client the flow was started under; a flow of another revision is dead. */
    record Flow(String flowId, String sub, String system, String state, SecretValue codeVerifier, String clientRevision) {

        @Override
        public String toString() {
            return "Flow[system=" + system + "]";
        }
    }

    /** Stores the flow and drops an earlier pending flow of the same user and system, so the latest link wins. */
    void start(Flow flow, Duration ttl);

    /** Reads without consuming. */
    Optional<Flow> peek(String flowId);

    /** Reads and removes in one step; only one of several concurrent callers gets the flow. */
    Optional<Flow> take(String flowId);

    /** Drops the pending flow of the user for each of the systems (offboarding). Idempotent. @return how many flows were pending */
    int discardAll(String sub, java.util.Collection<String> systems);
}
