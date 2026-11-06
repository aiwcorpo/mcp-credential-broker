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
        Instant accessExpiresAt,
        String clientRevision,
        boolean verified) {

    /** A connection whose secret was checked with a whoami (always the case but for a generic-rest system without one). */
    public Connection(String sub, String system, CredentialType type, StoredState state, String backendUser, Instant expiresAt,
            Instant connectedAt, Instant lastUsedAt, String secretVersion, Instant accessExpiresAt, String clientRevision) {
        this(sub, system, type, state, backendUser, expiresAt, connectedAt, lastUsedAt, secretVersion, accessExpiresAt,
                clientRevision, true);
    }

    /** Without a client revision: a connection of 1.x, or one a test builds. */
    public Connection(String sub, String system, CredentialType type, StoredState state, String backendUser, Instant expiresAt,
            Instant connectedAt, Instant lastUsedAt, String secretVersion, Instant accessExpiresAt) {
        this(sub, system, type, state, backendUser, expiresAt, connectedAt, lastUsedAt, secretVersion, accessExpiresAt, null, true);
    }

    public SecretKey secretKey() {
        return new SecretKey(sub, system, secretVersion);
    }

    public Connection withSecretVersion(String version) {
        return new Connection(sub, system, type, state, backendUser, expiresAt, connectedAt, lastUsedAt, version, accessExpiresAt, clientRevision, verified);
    }

    public Connection withAccessExpiresAt(Instant accessExpiry) {
        return new Connection(sub, system, type, state, backendUser, expiresAt, connectedAt, lastUsedAt, secretVersion, accessExpiry, clientRevision, verified);
    }

    public Connection withClientRevision(String revision) {
        return new Connection(sub, system, type, state, backendUser, expiresAt, connectedAt, lastUsedAt, secretVersion,
                accessExpiresAt, revision, verified);
    }

    /**
     * A grant is used with the definition it was issued under, and only with it. A connection without a revision matches
     * nothing: the import of 1.x gives the connections of a system its revision, so a row that still has none is one that
     * nobody vouches for.
     */
    public boolean issuedUnder(String systemClientRevision) {
        return clientRevision != null && clientRevision.equals(systemClientRevision);
    }

    public enum StoredState {
        CONNECTED, REVOKED, ERROR, NEEDS_RECONNECT
    }

    /** C4 status: expiring when the credential expires within the threshold (7 days by default). */
    public ConnectionStatus status(Instant now, Duration expiringThreshold) {
        return switch (state) {
            case REVOKED -> ConnectionStatus.REVOKED;
            case ERROR -> ConnectionStatus.ERROR;
            case NEEDS_RECONNECT -> ConnectionStatus.NEEDS_RECONNECT;
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
