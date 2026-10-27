package pl.aiwcorpo.mcp.broker.api;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonInclude;

/** C4 Connection: metadata only, never a secret value. */
@JsonInclude(JsonInclude.Include.ALWAYS)
public record ConnectionResponse(String system, String type, String status, String backendUser, Instant expiresAt,
        Instant connectedAt, Instant lastUsedAt) {
}
