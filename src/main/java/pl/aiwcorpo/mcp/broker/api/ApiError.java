package pl.aiwcorpo.mcp.broker.api;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Generic error body of C4 (CC-012); {@code message} is fixed text, never request content. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(String error, String message) {

    public static ApiError of(String error) {
        return new ApiError(error, null);
    }
}
