package pl.aiwcorpo.mcp.broker.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** C4 OAuthCompleteRequest. The authorization code is single-use but still a credential, so it never prints. */
public record OAuthCompleteRequest(
        @NotBlank @Size(max = 128) String flowId,
        @NotBlank @Size(max = 2048) String code,
        @NotBlank @Size(max = 512) String state) {

    @Override
    public String toString() {
        return "OAuthCompleteRequest[***]";
    }
}
