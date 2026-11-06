package pl.aiwcorpo.mcp.broker.api;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

/** C4 SystemAdminView: the configuration of a system without secrets. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SystemAdminView(String system, String baseUrl, String adapter, List<String> supportedTypes, String defaultType,
        String secretScheme, Oauth oauth) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Oauth(String clientId, String authorizeUrl, String tokenUrl, List<String> scopes, boolean clientSecretSet) {
    }
}
