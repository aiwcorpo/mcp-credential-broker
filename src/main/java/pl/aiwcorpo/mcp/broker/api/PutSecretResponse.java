package pl.aiwcorpo.mcp.broker.api;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.ALWAYS)
public record PutSecretResponse(String status, String backendUser, Instant expiresAt) {
}
