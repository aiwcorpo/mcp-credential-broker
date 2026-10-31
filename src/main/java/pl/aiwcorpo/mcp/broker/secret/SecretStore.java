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

    /** One stored value as the store lists it, without reading it. {@code version} is null for a value from before versions. */
    record Stored(String subHash, String system, String version, java.time.Instant updatedAt) {
    }

    /** Every stored value, for the sweep of values no connection row points at. */
    default java.util.List<Stored> listStored() {
        return java.util.List.of();
    }

    /** Removes one listed value with all its KV versions. Idempotent. */
    default void deleteStored(Stored stored) {
    }

    /** Removes every version of the secret. Idempotent. */
    void delete(SecretKey key);

    /**
     * Removes everything stored for the user under any system and version, including values no connection row points
     * at (left by a failed delete, or by a row that is gone). Idempotent; used by the offboarding purge.
     */
    void deleteAllOf(String sub);
}
