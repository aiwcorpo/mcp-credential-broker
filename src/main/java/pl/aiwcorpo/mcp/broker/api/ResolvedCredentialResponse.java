package pl.aiwcorpo.mcp.broker.api;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonInclude;

/** C4 ResolvedCredential; the only response body that carries a secret value. */
@JsonInclude(JsonInclude.Include.ALWAYS)
public record ResolvedCredentialResponse(String scheme, String value, String type, Instant expiresAt, int cacheTtlSeconds) {

    @Override
    public String toString() {
        return "ResolvedCredentialResponse[scheme=" + scheme + ", type=" + type + "]";
    }
}
