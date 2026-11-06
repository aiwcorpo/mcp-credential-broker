package pl.aiwcorpo.mcp.broker.api;

import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;

/**
 * C4 SystemAdminRequest. Unknown properties are rejected by strict JSON binding. The URLs stay strings: whether http is
 * allowed is a setting of the instance, checked by the service.
 */
public record SystemAdminRequest(
        @NotBlank @Size(max = 255) String baseUrl,
        @NotBlank String adapter,
        @NotEmpty List<@NotNull CredentialType> supportedTypes,
        @NotNull CredentialType defaultType,
        @NotNull CredentialScheme secretScheme,
        @Valid Oauth oauth) {

    public record Oauth(
            @NotBlank @Size(max = 255) String clientId,
            @Size(min = 1, max = 1024) String clientSecret,
            @NotBlank String authorizeUrl,
            @NotBlank String tokenUrl,
            List<@NotNull @Pattern(regexp = "^[!#-\\[\\]-~]{1,128}$") String> scopes) {

        /** The secret is never printed. */
        @Override
        public String toString() {
            return "Oauth[clientId=" + clientId + "]";
        }
    }
}
