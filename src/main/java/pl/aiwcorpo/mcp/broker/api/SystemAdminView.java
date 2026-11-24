package pl.aiwcorpo.mcp.broker.api;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

/** C4 SystemAdminView: the configuration of a system without secrets. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SystemAdminView(String system, String displayName, String baseUrl, String adapter, String product, List<String> supportedTypes,
        String defaultType, String secretScheme, String revokeUrl, String timeout, String exchangeAudience, String userSecretScheme,
        Oauth oauth, Whoami whoami, ServiceAccountKeySummary serviceAccountKey, boolean agentsAllowed) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Whoami(String path, String usernameField) {
    }

    /** {@code state} is set, missing or unknown (the secret store did not answer); the rest only with {@code set}. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ServiceAccountKeySummary(String state, String expiresAt, Boolean expired) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Oauth(String clientId, String authorizeUrl, String tokenUrl, List<String> scopes, boolean clientSecretSet) {
    }
}
