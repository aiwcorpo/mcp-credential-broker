package pl.aiwcorpo.mcp.broker.api;

public record CredentialRequiredResponse(String error, String system, String connectUrl) {
}
