package pl.aiwcorpo.mcp.broker.authenticator;

import java.util.Optional;

/**
 * Storage of TOTP seeds, the active one and the one of an enrollment in progress. Implementations fail closed:
 * any doubt about availability or integrity throws
 * {@link pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException}.
 */
public interface AuthenticatorSeedStore {

    /** Seed with the id of the registration (or enrollment) it belongs to; the bytes are never printed. */
    record Seed(String id, byte[] bytes) {

        @Override
        public String toString() {
            return "Seed[id=" + id + "]";
        }
    }

    void putActive(String sub, String registrationId, byte[] seed);

    Optional<Seed> getActive(String sub);

    /** Idempotent. */
    void deleteActive(String sub);

    void putPending(String sub, String enrollmentId, byte[] seed);

    Optional<Seed> getPending(String sub);

    /** Idempotent. */
    void deletePending(String sub);
}
