package pl.aiwcorpo.mcp.broker.authenticator;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.secret.OpenBaoClient;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Seeds on OpenBao (CC-092): the record is encrypted by Transit, without an envelope, and only the ciphertext is
 * written to KV v2 at {@code <kvMount>/data/<prefix>/<sha256(sub)>} (active) and {@code .../pending} (enrollment in
 * progress). The decrypted record names its owner and its kind, so a ciphertext copied to another user's path, or
 * from pending to active, is refused.
 */
public class OpenBaoAuthenticatorSeedStore implements AuthenticatorSeedStore {

    private static final int FORMAT_VERSION = 1;
    private static final String ACTIVE = "active";
    private static final String PENDING = "pending";

    private final OpenBaoClient client;
    private final BrokerProperties.OpenBao openbao;
    private final BrokerProperties.Authenticator config;
    private final JsonMapper json;

    public OpenBaoAuthenticatorSeedStore(OpenBaoClient client, BrokerProperties.OpenBao openbao,
            BrokerProperties.Authenticator config, JsonMapper json) {
        this.client = client;
        this.openbao = openbao;
        this.config = config;
        this.json = json;
    }

    @Override
    public void putActive(String sub, String registrationId, byte[] seed) {
        put(sub, ACTIVE, registrationId, seed);
    }

    @Override
    public Optional<Seed> getActive(String sub) {
        return get(sub, ACTIVE);
    }

    @Override
    public void deleteActive(String sub) {
        client.delete(metadataPath(sub, ACTIVE));
    }

    @Override
    public void putPending(String sub, String enrollmentId, byte[] seed) {
        put(sub, PENDING, enrollmentId, seed);
    }

    @Override
    public Optional<Seed> getPending(String sub) {
        return get(sub, PENDING);
    }

    @Override
    public void deletePending(String sub) {
        client.delete(metadataPath(sub, PENDING));
    }

    private void put(String sub, String kind, String id, byte[] seed) {
        ObjectNode plaintext = json.createObjectNode()
                .put("v", FORMAT_VERSION)
                .put("sub", sub)
                .put("kind", kind)
                .put("id", id)
                .put("seed", Base64.getEncoder().encodeToString(seed));
        String encoded = Base64.getEncoder().encodeToString(json.writeValueAsBytes(plaintext));
        JsonNode encrypted = client.write(transitPath("encrypt"), client.object().put("plaintext", encoded));
        JsonNode ciphertext = encrypted.path("data").path("ciphertext");
        if (!ciphertext.isString()) {
            throw new SecretStoreUnavailableException("transit encrypt returned no ciphertext");
        }
        ObjectNode body = client.object();
        body.set("data", client.object().put("ciphertext", ciphertext.stringValue()));
        client.write(dataPath(sub, kind), body);
    }

    private Optional<Seed> get(String sub, String kind) {
        JsonNode stored = client.read(dataPath(sub, kind));
        if (stored == null) {
            return Optional.empty();
        }
        JsonNode data = stored.path("data").path("data");
        if (data.isNull()) {
            // KV v2 answers data=null for a deleted version: that is "no seed", not an error.
            return Optional.empty();
        }
        JsonNode ciphertext = data.path("ciphertext");
        if (!ciphertext.isString()) {
            throw new SecretStoreUnavailableException("stored authenticator entry has no ciphertext");
        }
        JsonNode decrypted = client.write(transitPath("decrypt"), client.object().put("ciphertext", ciphertext.stringValue()));
        JsonNode encoded = decrypted.path("data").path("plaintext");
        if (!encoded.isString()) {
            throw new SecretStoreUnavailableException("transit decrypt returned no plaintext");
        }
        return Optional.of(parse(sub, kind, Base64.getDecoder().decode(encoded.stringValue())));
    }

    private Seed parse(String sub, String kind, byte[] plaintext) {
        JsonNode node;
        try {
            node = json.readTree(new String(plaintext, StandardCharsets.UTF_8));
        } catch (JacksonException e) {
            throw new SecretStoreUnavailableException("stored authenticator entry is not readable");
        }
        String id = node.path("id").asString(null);
        String seed = node.path("seed").asString(null);
        if (node.path("v").asInt(-1) != FORMAT_VERSION
                || !sub.equals(node.path("sub").asString(null))
                || !kind.equals(node.path("kind").asString(null))
                || id == null || id.isEmpty() || seed == null || seed.isEmpty()) {
            throw new SecretStoreUnavailableException("stored authenticator entry does not belong to this path");
        }
        return new Seed(id, Base64.getDecoder().decode(seed));
    }

    private String dataPath(String sub, String kind) {
        return openbao.kvMount() + "/data/" + relative(sub, kind);
    }

    private String metadataPath(String sub, String kind) {
        return openbao.kvMount() + "/metadata/" + relative(sub, kind);
    }

    private String relative(String sub, String kind) {
        String base = config.pathPrefix() + "/" + SecretKey.hashOf(sub);
        return ACTIVE.equals(kind) ? base : base + "/" + kind;
    }

    private String transitPath(String operation) {
        return openbao.transitMount() + "/" + operation + "/" + config.transitKey();
    }
}
