package pl.aiwcorpo.mcp.broker.auth;

import java.util.Optional;

import com.nimbusds.jose.jwk.ECKey;

/** Public keys of the gateway's internal JWT (C2 JWKS). */
public interface GatewayKeys {

    Optional<ECKey> find(String kid);
}
