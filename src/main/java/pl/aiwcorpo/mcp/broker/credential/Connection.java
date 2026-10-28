package pl.aiwcorpo.mcp.broker.credential;

import java.time.Duration;
import java.time.Instant;

import pl.aiwcorpo.mcp.broker.secret.SecretKey;

/**
 * Metadata of one (sub, system) connection; the value itself is in the secret store. {@code expiresAt} is the
 * date the user gave for a token (informational, user-secret only). {@code accessExpiresAt} is when the
 * current OAuth access token stops working; the broker renews it, so it never shows up as a C4 expiry.
 */
public record Connection(
        String sub,
        String system,
        CredentialType type,
        StoredState state,
        String backendUser,
        Instant expiresAt,
        Instant connectedAt,
        Instant lastUsedAt,
        String secretVersion,
        Instant accessExpiresAt) {

    public SecretKey secretKey() {
        return new SecretKey(sub, system, secretVersion);
    }

    public Connection withSecretVersion(String version) {
        return new Connection(sub, system, type, state, backendUser, expiresAt, connectedAt, lastUsedAt, version, accessExpiresAt);
    }

    public Connection withAccessExpiresAt(Instant accessExpiry) {
        return new Connection(sub, system, type, state, backendUser, expiresAt, connectedAt, lastUsedAt, secretVersion, accessExpiry);
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
