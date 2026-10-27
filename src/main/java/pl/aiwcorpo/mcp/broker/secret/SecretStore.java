package pl.aiwcorpo.mcp.broker.secret;

import java.util.Optional;

/**
 * Storage of credential values (D6). Implementations fail closed: any doubt about availability or
 * integrity throws {@link SecretStoreUnavailableException} instead of returning empty.
 */
public interface SecretStore {

    void put(SecretKey key, StoredCredential credential);

    Optional<StoredCredential> get(SecretKey key);

    /** Removes every version of the secret. Idempotent. */
    void delete(SecretKey key);
}
