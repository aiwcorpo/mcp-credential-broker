package pl.aiwcorpo.mcp.broker.api;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * C4 PutSecretRequest; unknown properties are rejected by strict JSON binding. {@code expiresAt} stays a
 * string so only the contract's UTC form (suffix Z) is accepted.
 */
public record PutSecretRequest(
        @NotNull @Size(min = 1, max = 4096) String secret,
        @Pattern(regexp = "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,9})?Z$") String expiresAt) {

    @Override
    public String toString() {
        return "PutSecretRequest[expiresAt=" + expiresAt + "]";
    }
}
