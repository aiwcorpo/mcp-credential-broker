package pl.aiwcorpo.mcp.broker.secret;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * {@link SecretStore} on OpenBao (D6). The credential is encrypted with Transit before it is written to
 * KV v2 at {@code <kvMount>/data/<pathPrefix>/<sha256(sub)>/<system>}, so a KV reader without the Transit
 * key sees only ciphertext. The plaintext names its owner (sub, system) and is checked on decrypt, so a
 * ciphertext copied to another user's path does not decrypt into a usable credential.
 */
public class OpenBaoSecretStore implements SecretStore {

    private static final int FORMAT_VERSION = 1;

    private final OpenBaoClient client;
    private final BrokerProperties.OpenBao config;
    private final JsonMapper json;

    public OpenBaoSecretStore(OpenBaoClient client, BrokerProperties.OpenBao config, JsonMapper json) {
        this.client = client;
        this.config = config;
        this.json = json;
    }

    @Override
    public void put(SecretKey key, StoredCredential credential) {
        ObjectNode plaintext = json.createObjectNode()
                .put("v", FORMAT_VERSION)
                .put("sub", key.sub())
                .put("system", key.system())
                .put("type", credential.type().wire())
                .put("value", credential.value().reveal());
        if (credential.refreshToken() != null) {
            plaintext.put("refreshToken", credential.refreshToken().reveal());
        }
        String encoded = Base64.getEncoder().encodeToString(json.writeValueAsBytes(plaintext));
        JsonNode encrypted = client.write(transitPath("encrypt"), client.object().put("plaintext", encoded));
        JsonNode ciphertext = encrypted.path("data").path("ciphertext");
        if (!ciphertext.isString()) {
            throw new SecretStoreUnavailableException("transit encrypt returned no ciphertext");
        }
        ObjectNode data = client.object().put("ciphertext", ciphertext.stringValue());
        ObjectNode body = client.object();
        body.set("data", data);
        client.write(dataPath(key), body);
    }

    @Override
    public Optional<StoredCredential> get(SecretKey key) {
        JsonNode stored = client.read(dataPath(key));
        if (stored == null) {
            return Optional.empty();
        }
        JsonNode ciphertext = stored.path("data").path("data").path("ciphertext");
        if (!ciphertext.isString()) {
            // KV v2 returns data=null for a deleted version; that is "no secret", not an error.
            if (stored.path("data").path("data").isNull()) {
                return Optional.empty();
            }
            throw new SecretStoreUnavailableException("stored entry has no ciphertext");
        }
        JsonNode decrypted = client.write(transitPath("decrypt"),
                client.object().put("ciphertext", ciphertext.stringValue()));
        JsonNode encoded = decrypted.path("data").path("plaintext");
        if (!encoded.isString()) {
            throw new SecretStoreUnavailableException("transit decrypt returned no plaintext");
        }
        return Optional.of(parse(key, Base64.getDecoder().decode(encoded.stringValue())));
    }

    @Override
    public void delete(SecretKey key) {
        client.delete(metadataPath(key));
    }

    private StoredCredential parse(SecretKey key, byte[] plaintext) {
        JsonNode node;
        try {
            node = json.readTree(new String(plaintext, StandardCharsets.UTF_8));
        } catch (JacksonException e) {
            throw new SecretStoreUnavailableException("stored entry is not readable");
        }
        if (node.path("v").asInt(-1) != FORMAT_VERSION
                || !key.sub().equals(node.path("sub").asString(null))
                || !key.system().equals(node.path("system").asString(null))) {
            throw new SecretStoreUnavailableException("stored entry does not belong to this path");
        }
        CredentialType type = CredentialType.fromWire(node.path("type").asString(null)).orElse(null);
        String value = node.path("value").asString(null);
        if (type == null || value == null || value.isEmpty()) {
            throw new SecretStoreUnavailableException("stored entry is incomplete");
        }
        String refresh = node.path("refreshToken").asString(null);
        return new StoredCredential(type, SecretValue.of(value),
                refresh == null || refresh.isEmpty() ? null : SecretValue.of(refresh));
    }

    private String dataPath(SecretKey key) {
        return config.kvMount() + "/data/" + relative(key);
    }

    private String metadataPath(SecretKey key) {
        return config.kvMount() + "/metadata/" + relative(key);
    }

    private String relative(SecretKey key) {
        return config.pathPrefix() + "/" + key.subHash() + "/" + key.system();
    }

    private String transitPath(String operation) {
        return config.transitMount() + "/" + operation + "/" + config.transitKey();
    }
}
