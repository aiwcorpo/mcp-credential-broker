package pl.aiwcorpo.mcp.broker.system;

import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;

/**
 * A REST system that is reached with the platform's own key (Service Desk): the broker only hands the key out
 * and calls the system never, so there is no whoami and users have no connection to it.
 */
public class GenericRestAdapter implements ServiceAccountSource {

    private final String system;
    private final CredentialScheme scheme;
    private final ServiceAccountKeys keys;

    public GenericRestAdapter(String system, CredentialScheme scheme, ServiceAccountKeys keys) {
        this.system = system;
        this.scheme = scheme;
        this.keys = keys;
    }

    @Override
    public ServiceAccountKeys.Key key() {
        return keys.read(system, scheme);
    }
}
