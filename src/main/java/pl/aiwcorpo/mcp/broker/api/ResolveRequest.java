package pl.aiwcorpo.mcp.broker.api;

import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** C4 ResolveRequest. {@code subjectToken} is used only by token-exchange systems (M3) and never logged. */
public record ResolveRequest(
        @NotNull String system,
        List<@NotNull @NotBlank String> scopes,
        @Size(min = 1) String subjectToken) {

    @Override
    public String toString() {
        return "ResolveRequest[system=" + system + "]";
    }
}
