package pl.aiwcorpo.mcp.broker.credential;

import java.util.Arrays;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonValue;

/** Credential types of C4.2; the wire value is the one used in C3 and C4. */
public enum CredentialType {
    USER_OAUTH("user-oauth"),
    USER_SECRET("user-secret"),
    TOKEN_EXCHANGE("token-exchange"),
    SERVICE_ACCOUNT("service-account");

    private final String wire;

    CredentialType(String wire) {
        this.wire = wire;
    }

    @JsonValue
    public String wire() {
        return wire;
    }

    public static Optional<CredentialType> fromWire(String value) {
        return Arrays.stream(values()).filter(type -> type.wire.equals(value)).findFirst();
    }
}
