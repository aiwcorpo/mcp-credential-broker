package pl.aiwcorpo.mcp.broker.secret;

import java.util.Optional;

/**
 * Storage of credential values (D6). Implementations fail closed: any doubt about availability or
 * integrity throws {@link SecretStoreUnavailableException} instead of returning empty.
 */
public interface SecretStore {

    void put(SecretKey key, StoredCredential credential);

    /**
     * Writes a credential the provider has just rotated, replacing one it has already spent. Same as {@link #put}
     * unless the implementation has a fast-failure mode, which this write must not be refused by.
     */
    default void putRotated(SecretKey key, StoredCredential credential) {
        put(key, credential);
    }

    Optional<StoredCredential> get(SecretKey key);

    /** Removes every version of the secret. Idempotent. */
    void delete(SecretKey key);

    /**
     * Removes everything stored for the user under any system and version, including values no connection row points
     * at (left by a failed delete, or by a row that is gone). Idempotent; used by the offboarding purge.
     */
    void deleteAllOf(String sub);
}
