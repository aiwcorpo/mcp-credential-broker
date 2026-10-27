package pl.aiwcorpo.mcp.broker.credential;

import com.fasterxml.jackson.annotation.JsonValue;

public enum ConnectionStatus {
    CONNECTED("connected"),
    EXPIRING("expiring"),
    EXPIRED("expired"),
    REVOKED("revoked"),
    ERROR("error");

    private final String wire;

    ConnectionStatus(String wire) {
        this.wire = wire;
    }

    @JsonValue
    public String wire() {
        return wire;
    }

    public boolean usable() {
        return this == CONNECTED || this == EXPIRING;
    }
}
