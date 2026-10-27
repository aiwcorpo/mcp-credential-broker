package pl.aiwcorpo.mcp.broker.api;

import java.util.List;

public record SystemInfoResponse(String system, List<String> supportedTypes, String defaultType, List<String> oauthScopes) {
}
