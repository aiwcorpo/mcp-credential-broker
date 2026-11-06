package pl.aiwcorpo.mcp.broker.api;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record SystemInfoResponse(String system, List<String> supportedTypes, String defaultType, List<String> oauthScopes,
        String deployment, String userSecretScheme, String displayName, Boolean userSecretVerified) {
}
