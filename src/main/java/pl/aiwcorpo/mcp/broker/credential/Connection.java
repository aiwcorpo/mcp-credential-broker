package pl.aiwcorpo.mcp.broker.credential;

import java.time.Duration;
import java.time.Instant;

import pl.aiwcorpo.mcp.broker.secret.SecretKey;

/** Metadata of one (sub, system) connection; the value itself is in the secret store. */
public record Connection(
        String sub,
        String system,
        CredentialType type,
        StoredState state,
        String backendUser,
        Instant expiresAt,
        Instant connectedAt,
        Instant lastUsedAt,
        String secretVersion) {

    public SecretKey secretKey() {
        return new SecretKey(sub, system, secretVersion);
    }

    public enum StoredState {
        CONNECTED, REVOKED, ERROR
    }

    /** C4 status: expiring when the credential expires within the threshold (7 days by default). */
    public ConnectionStatus status(Instant now, Duration expiringThreshold) {
        return switch (state) {
            case REVOKED -> ConnectionStatus.REVOKED;
            case ERROR -> ConnectionStatus.ERROR;
            case CONNECTED -> {
                if (expiresAt == null) {
                    yield ConnectionStatus.CONNECTED;
                }
                if (!now.isBefore(expiresAt)) {
                    yield ConnectionStatus.EXPIRED;
                }
                yield now.plus(expiringThreshold).isAfter(expiresAt) ? ConnectionStatus.EXPIRING : ConnectionStatus.CONNECTED;
            }
        };
    }
}
