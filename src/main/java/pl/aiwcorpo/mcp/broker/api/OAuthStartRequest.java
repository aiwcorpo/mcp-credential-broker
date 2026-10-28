package pl.aiwcorpo.mcp.broker.api;

import jakarta.validation.constraints.NotNull;

/** C4 OAuthStartRequest; the shape of {@code returnPath} is checked by the service (CC-032). */
public record OAuthStartRequest(@NotNull String returnPath) {
}
