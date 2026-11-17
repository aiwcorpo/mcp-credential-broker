package pl.aiwcorpo.mcp.broker.api;

import com.fasterxml.jackson.annotation.JsonInclude;

/** C4 ServiceAccountKeyStatus: what is known about the key without revealing it. Only {@code system} and {@code set} when there is no entry. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ServiceAccountKeyStatus(String system, boolean set, Integer kvVersion, String expiresAt, Boolean expired,
        String updatedAt, String updatedBy) {
}
