package pl.aiwcorpo.mcp.broker.system;

import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;

/** The key of the platform's own account in a target system (C4.2 service-account). */
public interface ServiceAccountSource {

    /**
     * The key and its expiry (null when the key has no planned end). Throws
     * {@link pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException} when there is no usable key.
     */
    ServiceAccountKeys.Key key();
}
