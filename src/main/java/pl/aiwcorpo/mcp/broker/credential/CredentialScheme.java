package pl.aiwcorpo.mcp.broker.credential;

import com.fasterxml.jackson.annotation.JsonValue;

/** Scheme of the X-MCP-Credential header value (C3). */
public enum CredentialScheme {
    BEARER("Bearer"),
    BASIC("Basic"),
    TOKEN("Token"),
    API_KEY("ApiKey");

    private final String wire;

    CredentialScheme(String wire) {
        this.wire = wire;
    }

    @JsonValue
    public String wire() {
        return wire;
    }
}
