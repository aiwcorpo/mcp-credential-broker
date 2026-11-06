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
        @Pattern(regexp = "^[^\\p{Cc}\\p{Cf}\\p{Cs}\\u2028\\u2029]{1,64}$") String displayName,
        @Pattern(regexp = "^(jira|confluence)$") String product,
        @NotEmpty List<@NotNull CredentialType> supportedTypes,
        @NotNull CredentialType defaultType,
        @NotNull CredentialScheme secretScheme,
        @Size(max = 255) String revokeUrl,
        @Pattern(regexp = "^PT(?:[1-9][0-9]{0,2}S|[1-9]M(?:[0-5]?[0-9]S)?|10M)$") String timeout,
        @Size(min = 1, max = 255) String exchangeAudience,
        CredentialScheme userSecretScheme,
        @Valid Oauth oauth) {

    public record Oauth(
            @NotBlank @Size(max = 255) String clientId,
            @Size(min = 1, max = 1024) String clientSecret,
            @Size(max = 255) String authorizeUrl,
            @Size(max = 255) String tokenUrl,
            List<@NotNull @Pattern(regexp = "^[!#-\\[\\]-~]{1,128}$") String> scopes) {

        /** The secret is never printed. */
        @Override
        public String toString() {
            return "Oauth[clientId=" + clientId + "]";
        }
    }
}
