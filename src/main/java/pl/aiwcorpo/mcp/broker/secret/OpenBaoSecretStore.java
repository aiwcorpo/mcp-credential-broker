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
 * KV v2 at {@code <kvMount>/data/<pathPrefix>/<sha256(sub)>/<system>/<version>}, so a KV reader without the Transit
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
    public void putRotated(SecretKey key, StoredCredential credential) {
        client.bypassingBreaker(() -> {
            put(key, credential);
            return null;
        });
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
            throw new SecretUnreadableException("stored entry has no ciphertext");
        }
        JsonNode decrypted = decrypt(ciphertext.stringValue());
        JsonNode encoded = decrypted.path("data").path("plaintext");
        if (!encoded.isString()) {
            throw new SecretUnreadableException("transit decrypt returned no plaintext");
        }
        return Optional.of(parse(key, Base64.getDecoder().decode(encoded.stringValue())));
    }

    /**
     * Only Transit's own verdicts on a damaged ciphertext make an entry unreadable for good. Any other refusal (a missing
     * key, a policy) is the installation's fault and stays a failure to be retried.
     */
    private JsonNode decrypt(String ciphertext) {
        try {
            return client.write(transitPath("decrypt"), client.object().put("ciphertext", ciphertext));
        } catch (StoreRefusedException e) {
            // "version is too new" is a key that is not (yet) here, as after a restore: not damage, and retrying may help.
            if (e.reason().equals("cipher: message authentication failed")
                    || e.reason().startsWith("invalid ciphertext") && !e.reason().contains("version is too new")) {
                throw new SecretUnreadableException("transit refused the stored ciphertext as damaged");
            }
            throw e;
        }
    }

    @Override
    public void delete(SecretKey key) {
        client.delete(metadataPath(key));
    }

    @Override
    public void deleteAllOf(String sub) {
        deleteBelow(config.kvMount() + "/metadata/" + config.pathPrefix() + "/" + SecretKey.hashOf(sub) + "/");
    }

    @Override
    public java.util.List<Stored> listStored() {
        String root = config.kvMount() + "/metadata/" + config.pathPrefix() + "/";
        java.util.List<Stored> found = new java.util.ArrayList<>();
        for (String hash : names(client.list(root))) {
            if (!hash.endsWith("/")) {
                continue;
            }
            String subHash = hash.substring(0, hash.length() - 1);
            for (String systemEntry : names(client.list(root + hash))) {
                if (systemEntry.endsWith("/")) {
                    String system = systemEntry.substring(0, systemEntry.length() - 1);
                    for (String version : names(client.list(root + hash + systemEntry))) {
                        if (!version.endsWith("/")) {
                            found.add(new Stored(subHash, system, version, updatedAt(root + hash + systemEntry + version)));
                        }
                    }
                } else {
                    found.add(new Stored(subHash, systemEntry, null, updatedAt(root + hash + systemEntry)));
                }
            }
        }
        return found;
    }

    @Override
    public void deleteStored(Stored stored) {
        client.delete(config.kvMount() + "/metadata/" + config.pathPrefix() + "/" + stored.subHash() + "/" + stored.system()
                + (stored.version() == null ? "" : "/" + stored.version()));
    }

    private static java.util.List<String> names(JsonNode listed) {
        java.util.List<String> names = new java.util.ArrayList<>();
        if (listed != null) {
            for (JsonNode entry : listed.path("data").path("keys")) {
                String name = entry.asString("");
                if (name.isEmpty() || name.contains("..") || name.startsWith("/")) {
                    throw new SecretStoreUnavailableException("secret store listed an unexpected entry");
                }
                names.add(name);
            }
        }
        return names;
    }

    private java.time.Instant updatedAt(String metadataPath) {
        JsonNode metadata = client.read(metadataPath);
        String updated = metadata == null ? null : metadata.path("data").path("updated_time").asString(null);
        return updated == null ? java.time.Instant.EPOCH : java.time.Instant.parse(updated);
    }

    /** KV v2 lists a folder as {@code name/} and a secret as {@code name}; a metadata delete removes all versions of a secret. */
    private void deleteBelow(String folder) {
        JsonNode listed = client.list(folder);
        if (listed == null) {
            return;
        }
        for (JsonNode entry : listed.path("data").path("keys")) {
            String name = entry.asString("");
            if (name.isEmpty() || name.contains("..") || name.startsWith("/")) {
                throw new SecretStoreUnavailableException("secret store listed an unexpected entry");
            }
            if (name.endsWith("/")) {
                deleteBelow(folder + name);
            } else {
                client.delete(folder + name);
            }
        }
    }

    private StoredCredential parse(SecretKey key, byte[] plaintext) {
        JsonNode node;
        try {
            node = json.readTree(new String(plaintext, StandardCharsets.UTF_8));
        } catch (JacksonException e) {
            throw new SecretUnreadableException("stored entry is not readable");
        }
        if (node.path("v").asInt(-1) != FORMAT_VERSION
                || !key.sub().equals(node.path("sub").asString(null))
                || !key.system().equals(node.path("system").asString(null))) {
            throw new SecretUnreadableException("stored entry does not belong to this path");
        }
        CredentialType type = CredentialType.fromWire(node.path("type").asString(null)).orElse(null);
        String value = node.path("value").asString(null);
        if (type == null || value == null || value.isEmpty()) {
            throw new SecretUnreadableException("stored entry is incomplete");
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
        return config.pathPrefix() + "/" + key.relativePath();
    }

    private String transitPath(String operation) {
        return config.transitMount() + "/" + operation + "/" + config.transitKey();
    }
}
