package pl.aiwcorpo.mcp.broker.api;

public record OAuthCompleteResponse(String status, String backendUser, boolean verified) {
}
