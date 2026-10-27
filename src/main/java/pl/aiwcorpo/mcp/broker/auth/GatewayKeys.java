package pl.aiwcorpo.mcp.broker.auth;

import java.util.Optional;

import com.nimbusds.jose.jwk.ECKey;

/** Public keys of the gateway's internal JWT (C2 JWKS). */
public interface GatewayKeys {

    /** Empty for an unknown kid; throws {@link KeySourceUnavailableException} when keys cannot be trusted now. */
    Optional<ECKey> find(String kid);
}
