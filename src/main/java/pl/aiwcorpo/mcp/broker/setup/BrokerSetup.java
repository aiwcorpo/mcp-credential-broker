package pl.aiwcorpo.mcp.broker.setup;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.ConnectException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertPathValidatorException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

import com.nimbusds.jose.jwk.JWKSet;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * First-start setup of one credential broker installation, run as {@code java -jar app.jar init [dir]} before the broker starts
 * (the init service of deploy/compose.yaml, ExecStartPre of the systemd unit).
 *
 * <p>Every value the operator did not set in the environment and that nothing outside this installation needs to know is generated
 * once into {@code dir} and kept: the passwords of the installation's own PostgreSQL and Redis and the Redis ACL and configuration.
 * A second run changes nothing. The broker reads {@code dir/broker/env} as a Spring config tree.
 *
 * <p>Then it checks what it cannot generate (addresses, certificates, the AppRole) the way the broker will use it, and stops with exit
 * code 1 and the likely cause when the broker could not work. The gateway only warns, because it may be installed after the broker.
 * The broker trusts only its outbound truststore (MCP_TLS_OUTBOUND_TRUSTSTORE, else MCP_TLS_TRUSTSTORE) for every outgoing TLS
 * connection (identity provider, OpenBao, gateway), so the checks do the same and never fall back to the JVM store.
 */
public final class BrokerSetup {

    static final List<String> REQUIRED = List.of("MCP_PORTAL_URL", "MCP_OIDC_ISSUER", "MCP_OIDC_JWKS_URI", "MCP_BAO_ADDR",
            "MCP_BAO_ROLE_ID", "MCP_BAO_SECRET_ID", "MCP_TLS_KEYSTORE", "MCP_TLS_TRUSTSTORE", "MCP_TLS_STORE_PASSWORD", "MCP_DB_URL",
            "MCP_DB_USER", "MCP_DB_PASSWORD", "MCP_REDIS_HOST", "MCP_REDIS_PASSWORD");

    /** What the AppRole policy of the README grants, as paths of OpenBao with the capability the broker needs on each. */
    static final Map<String, String> POLICY_PROBES = Map.of(
            "secret/data/mcp/connections/probe", "create",
            "secret/data/mcp/system-clients/probe", "create",
            "secret/data/mcp/authenticators/probe", "create",
            "secret/data/mcp/service-accounts/probe", "read",
            "transit/encrypt/mcp-credential-broker", "update",
            "transit/decrypt/mcp-authenticators", "update");

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final Map<String, String> env;
    private final Path dir;
    private final PrintStream out;
    private int failures;

    BrokerSetup(Map<String, String> env, Path dir, PrintStream out) {
        this.env = new LinkedHashMap<>(env);
        this.dir = dir;
        this.out = out;
    }

    public static int run(String[] args) {
        Path dir = Path.of(args.length > 1 ? args[1] : "/secrets");
        return new BrokerSetup(System.getenv(), dir, System.out).run();
    }

    int run() {
        try {
            generate();
        } catch (IOException e) {
            out.println("FAIL  cannot write to " + dir + ": " + e.getMessage());
            return 1;
        }
        check();
        if (failures > 0) {
            out.println();
            out.println(failures + " problem(s): fix them in the configuration and start again. Generated values are kept.");
            return 1;
        }
        out.println();
        out.println("Ready to start.");
        return 0;
    }

    void generate() throws IOException {
        Path brokerEnv = dir.resolve("broker").resolve("env");
        Files.createDirectories(brokerEnv);
        restrict(dir.resolve("broker"));
        String db = generated(brokerEnv, "MCP_DB_PASSWORD");
        if (db != null) {
            Path postgres = dir.resolve("postgres").resolve("password");
            createSharedDirectory(postgres.getParent());
            writeShared(postgres, db);
        }
        String redis = generated(brokerEnv, "MCP_REDIS_PASSWORD");
        if (redis != null) {
            writeRedis(redis);
        }
        // The checks below see what the broker will see.
        try (var files = Files.list(brokerEnv)) {
            for (Path file : files.filter(f -> !f.getFileName().toString().startsWith(".")).toList()) {
                env.putIfAbsent(file.getFileName().toString(), Files.readString(file).strip());
            }
        }
    }

    /**
     * Configuration of the installation's own Redis. The ACL gives the broker its key prefixes, its one channel and the commands it
     * uses, nothing else; the password stays in a file, never in a command line.
     */
    private void writeRedis(String brokerPassword) throws IOException {
        Path redisDir = dir.resolve("redis");
        createSharedDirectory(redisDir);
        writeShared(redisDir.resolve("users.acl"), "user default off resetkeys resetchannels -@all\n"
                + "user " + env.getOrDefault("MCP_REDIS_USER", "broker") + " on #" + sha256(brokerPassword) + " " + redisRules() + "\n");
        // noeviction: one-time OAuth flows, locks and the jti of internal tokens must never be evicted to make room;
        // appendonly: they survive a restart.
        writeShared(redisDir.resolve("redis.conf"),
                "aclfile /secrets/redis/users.acl\ndir /data\nappendonly yes\nappendfsync everysec\nmaxmemory-policy noeviction\n");
    }

    /** The value of {@code name} when this installation owns it (not set by the operator), generated on the first run. */
    private String generated(Path brokerEnv, String name) throws IOException {
        if (env.containsKey(name)) {
            return null;
        }
        Path file = brokerEnv.resolve(name);
        if (Files.exists(file)) {
            return Files.readString(file).strip();
        }
        String value = randomSecret();
        writeSecret(file, value);
        out.println("new   " + name);
        return value;
    }

    void check() {
        List<String> missing = new ArrayList<>(REQUIRED.stream().filter(name -> blank(env.get(name))).toList());
        if (blank(env.get("MCP_GATEWAY_JWKS_FILE"))) {
            Stream.of("MCP_GATEWAY_JWKS_URI", "MCP_GATEWAY_TLS_NAME").filter(name -> blank(env.get(name))).forEach(missing::add);
        } else if (!blank(env.get("MCP_GATEWAY_JWKS_URI"))) {
            missing.add("only one of MCP_GATEWAY_JWKS_URI and MCP_GATEWAY_JWKS_FILE");
        }
        if (!missing.isEmpty()) {
            fail("not set: " + String.join(", ", missing));
            return;
        }
        boolean plainHttp = "true".equalsIgnoreCase(env.get("MCP_ALLOW_PLAIN_HTTP"));
        for (String name : List.of("MCP_PORTAL_URL", "MCP_OIDC_JWKS_URI", "MCP_BAO_ADDR")) {
            requireHttps(name, plainHttp);
        }
        if (!blank(env.get("MCP_GATEWAY_JWKS_URI"))) {
            requireHttps("MCP_GATEWAY_JWKS_URI", plainHttp);
            checkGatewayName();
        }
        checkAllowedAzp();
        HttpClient http = httpClient();
        if (http == null) {
            return;
        }
        checkIdentityProvider(http);
        checkOpenBao(http);
        checkGateway(http);
    }

    private void requireHttps(String name, boolean plainHttp) {
        String value = env.get(name);
        if (!value.startsWith("https://") && !(plainHttp && value.startsWith("http://"))) {
            fail(name + " " + value + " must start with https://");
        }
    }

    /** The broker verifies the gateway certificate against the host of the URL, so a different name could not be enforced. */
    private void checkGatewayName() {
        String host = URI.create(env.get("MCP_GATEWAY_JWKS_URI")).getHost();
        if (host != null && !host.equalsIgnoreCase(env.get("MCP_GATEWAY_TLS_NAME"))) {
            fail("MCP_GATEWAY_JWKS_URI host " + host + " must equal MCP_GATEWAY_TLS_NAME " + env.get("MCP_GATEWAY_TLS_NAME")
                    + ": the broker refuses to start otherwise");
        }
    }

    private void checkAllowedAzp() {
        String configured = env.get("MCP_BFF_ALLOWED_AZP");
        if (blank(configured)) {
            ok("BFF clients: mcp-portal-bff (MCP_BFF_ALLOWED_AZP not set)");
            return;
        }
        List<String> clients = List.of(configured.split(",")).stream().map(String::strip).toList();
        if (clients.stream().anyMatch(client -> !client.matches("[A-Za-z0-9._-]{1,128}"))) {
            fail("MCP_BFF_ALLOWED_AZP " + configured + " must be client ids (the azp of the portal's token) separated by commas");
            return;
        }
        ok("BFF clients: " + String.join(", ", clients));
    }

    /**
     * The client the broker uses for every outgoing TLS connection: it trusts the outbound truststore only. Null when the files are
     * unusable.
     */
    private HttpClient httpClient() {
        Path keystore = Path.of(env.get("MCP_TLS_KEYSTORE"));
        Path truststore = Path.of(env.get("MCP_TLS_TRUSTSTORE"));
        String outboundSetting = env.get("MCP_TLS_OUTBOUND_TRUSTSTORE");
        Path outbound = outboundSetting == null ? truststore : Path.of(outboundSetting);
        if (outboundSetting != null && outboundSetting.isBlank()) {
            fail("MCP_TLS_OUTBOUND_TRUSTSTORE is empty: remove it to use MCP_TLS_TRUSTSTORE, or name a file");
            return null;
        }
        for (Path file : List.of(keystore, truststore, outbound)) {
            if (!Files.isReadable(file)) {
                fail("certificate file " + file + " does not exist or cannot be read");
                return null;
            }
        }
        char[] password = env.get("MCP_TLS_STORE_PASSWORD").toCharArray();
        try {
            KeyStore keys = load(keystore, password);
            KeyStore trust = load(truststore, password);
            KeyStore outboundTrust = outbound.equals(truststore) ? trust : load(outbound, password);
            if (Collections.list(keys.aliases()).stream().noneMatch(alias -> isKey(keys, alias))) {
                fail("keystore " + keystore + " has no private key: it must hold the certificate of the broker and its key");
                return null;
            }
            if (trust.size() == 0) {
                fail("truststore " + truststore + " has no certificate: it must hold the internal CA");
                return null;
            }
            if (outboundTrust.size() == 0) {
                fail("outbound truststore " + outbound + " has no certificate: it must hold the internal CA");
                return null;
            }
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(outboundTrust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), null);
            ok("broker certificate " + keystore + " and truststore " + truststore
                    + (outbound.equals(truststore) ? "" : ", outbound truststore " + outbound));
            return HttpClient.newBuilder().sslContext(context).connectTimeout(CONNECT_TIMEOUT)
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        } catch (GeneralSecurityException | IOException e) {
            // PKCS12 reports a wrong password as a failed decryption.
            boolean wrongPassword = inChain(e, javax.crypto.BadPaddingException.class)
                    || inChain(e, java.security.UnrecoverableKeyException.class) || chainMentions(e, "password");
            fail("cannot open " + keystore + ", " + truststore + (outbound.equals(truststore) ? "" : " or " + outbound) + ": "
                    + (wrongPassword ? "wrong MCP_TLS_STORE_PASSWORD (every store uses it)" : rootMessage(e)));
            return null;
        }
    }

    private static boolean isKey(KeyStore store, String alias) {
        try {
            return store.isKeyEntry(alias);
        } catch (java.security.KeyStoreException e) {
            return false;
        }
    }

    private static KeyStore load(Path file, char[] password) throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(file)) {
            store.load(in, password);
        }
        return store;
    }

    private void checkIdentityProvider(HttpClient http) {
        String url = env.get("MCP_OIDC_JWKS_URI");
        HttpResponse<String> response = get("identity provider keys", url, http, true);
        if (response == null) {
            return;
        }
        try {
            if (response.statusCode() != 200 || JWKSet.parse(response.body()).getKeys().isEmpty()) {
                fail("identity provider keys " + url + ": HTTP " + response.statusCode() + " without keys; check MCP_OIDC_JWKS_URI");
                return;
            }
            ok("identity provider keys " + url);
        } catch (java.text.ParseException e) {
            fail("identity provider keys " + url + ": not a JWKS document; check MCP_OIDC_JWKS_URI");
        }
    }

    private void checkOpenBao(HttpClient http) {
        String address = env.get("MCP_BAO_ADDR");
        HttpResponse<String> login = send("OpenBao " + address, http, true,
                request(address, "auth/approle/login", null).POST(HttpRequest.BodyPublishers.ofString(JSON.createObjectNode()
                        .put("role_id", env.get("MCP_BAO_ROLE_ID")).put("secret_id", env.get("MCP_BAO_SECRET_ID")).toString())));
        if (login == null) {
            return;
        }
        String token = login.statusCode() == 200 ? clientToken(login.body()) : null;
        if (token == null) {
            fail("OpenBao " + address + ": " + loginRefusal(login.statusCode()));
            return;
        }
        ok("OpenBao " + address + ": AppRole login works");
        checkPolicy(http, address, token);
    }

    /** Names the broker's rights that the policy lacks. Only a warning: the policy can be completed while the broker runs. */
    private void checkPolicy(HttpClient http, String address, String token) {
        var paths = JSON.createObjectNode().putArray("paths");
        POLICY_PROBES.keySet().stream().sorted().forEach(paths::add);
        HttpResponse<String> response = send("OpenBao " + address, http, false,
                request(address, "sys/capabilities-self", token).POST(HttpRequest.BodyPublishers
                        .ofString(JSON.createObjectNode().set("paths", paths).toString())));
        if (response == null) {
            return;
        }
        if (response.statusCode() != 200) {
            out.println("warn  OpenBao policy not verified: sys/capabilities-self answered HTTP " + response.statusCode());
            return;
        }
        List<String> lacking = new ArrayList<>();
        try {
            JsonNode answer = JSON.readTree(response.body());
            // OpenBao repeats the paths at the top level and under "data".
            JsonNode body = answer.has("data") ? answer.path("data") : answer;
            POLICY_PROBES.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(probe -> {
                JsonNode capabilities = body.path(probe.getKey());
                boolean granted = capabilities.isArray() && capabilities.valueStream()
                        .anyMatch(c -> "root".equals(c.asString("")) || probe.getValue().equals(c.asString("")));
                if (!granted) {
                    lacking.add(probe.getValue() + " on " + probe.getKey());
                }
            });
        } catch (JacksonException e) {
            out.println("warn  OpenBao policy not verified: the answer of sys/capabilities-self is not JSON");
            return;
        }
        if (lacking.isEmpty()) {
            ok("OpenBao policy covers the paths the broker uses");
        } else {
            out.println("warn  OpenBao policy of the AppRole lacks: " + String.join("; ", lacking)
                    + " (the policy in deploy/README.md; the KV v2 mount secret/ and the transit keys must exist too)");
        }
    }

    private static String clientToken(String body) {
        try {
            JsonNode token = JSON.readTree(body).path("auth").path("client_token");
            return token.isString() && !token.stringValue().isEmpty() ? token.stringValue() : null;
        } catch (JacksonException e) {
            return null;
        }
    }

    /** The body is never printed: an answer of the login endpoint may carry secret material. */
    private static String loginRefusal(int status) {
        return switch (status) {
            case 400 -> "AppRole login refused (HTTP 400): MCP_BAO_ROLE_ID or MCP_BAO_SECRET_ID is wrong, or the secret_id has expired";
            case 403 -> "AppRole login refused (HTTP 403): the AppRole is bound to other addresses, or permission denied";
            case 404 -> "no AppRole login at this address (HTTP 404): MCP_BAO_ADDR is wrong, or the approle auth method is not enabled";
            case 429, 500, 502, 503 -> "OpenBao answered HTTP " + status + ": it is sealed, not initialised, or not ready";
            default -> "AppRole login failed with HTTP " + status;
        };
    }

    /** Only a warning: the gateway may be installed before or after the broker. */
    private void checkGateway(HttpClient http) {
        if (!blank(env.get("MCP_GATEWAY_JWKS_FILE"))) {
            Path file = Path.of(env.get("MCP_GATEWAY_JWKS_FILE"));
            if (Files.isReadable(file)) {
                ok("gateway keys " + file);
            } else {
                out.println("warn  gateway keys file " + file + " does not exist or cannot be read");
            }
            return;
        }
        String url = env.get("MCP_GATEWAY_JWKS_URI");
        HttpResponse<String> response = get("gateway keys", url, http, false);
        if (response == null) {
            return;
        }
        if (response.statusCode() == 200) {
            ok("gateway keys " + url);
        } else {
            out.println("warn  gateway keys " + url + ": HTTP " + response.statusCode());
        }
    }

    private HttpRequest.Builder request(String address, String path, String token) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(address).resolve("/v1/" + path))
                .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json").header("Accept", "application/json");
        return token == null ? request : request.header("X-Vault-Token", token);
    }

    private HttpResponse<String> get(String what, String url, HttpClient http, boolean required) {
        try {
            return send(what + " " + url, http, required, HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET());
        } catch (IllegalArgumentException e) {
            report(required, what + " " + url + ": not a valid URL");
            return null;
        }
    }

    /** Any HTTP answer is returned: it proves the name, the route and the certificate. */
    private HttpResponse<String> send(String what, HttpClient http, boolean required, HttpRequest.Builder request) {
        try {
            return http.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            report(required, what + ": not a valid URL");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            report(required, what + ": interrupted");
        } catch (IOException e) {
            report(required, what + ": " + cause(e));
        }
        return null;
    }

    /** The most specific cause anywhere in the chain wins: an unresolved name also arrives wrapped in a ConnectException. */
    static String cause(Throwable e) {
        if (inChain(e, UnknownHostException.class) || inChain(e, java.nio.channels.UnresolvedAddressException.class)) {
            return "the name does not resolve from this host (DNS or /etc/hosts)";
        }
        if (inChain(e, HttpConnectTimeoutException.class)) {
            return "no answer within " + CONNECT_TIMEOUT.toSeconds() + " s; a firewall drops the connection";
        }
        if (inChain(e, CertPathValidatorException.class) || chainMentions(e, "PKIX path")) {
            return "its certificate is not signed by a CA in MCP_TLS_OUTBOUND_TRUSTSTORE, or MCP_TLS_TRUSTSTORE when that is not set "
                    + "(the broker trusts only that store, also for the identity provider and OpenBao)";
        }
        if (chainMentions(e, "No subject alternative") || chainMentions(e, "No name matching")) {
            return "its certificate does not name the host of the address in subjectAltName";
        }
        if (inChain(e, ConnectException.class)) {
            return "connection refused; nothing listens on that port, or the service is not running yet";
        }
        if (inChain(e, HttpTimeoutException.class)) {
            return "connected, but no answer within 10 s";
        }
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof SSLException) {
                return "TLS failed: " + t.getMessage();
            }
        }
        return Objects.requireNonNullElse(rootMessage(e), e.getClass().getSimpleName());
    }

    private static boolean inChain(Throwable e, Class<? extends Throwable> type) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (type.isInstance(t)) {
                return true;
            }
        }
        return false;
    }

    private static boolean chainMentions(Throwable e, String text) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (String.valueOf(t.getMessage()).contains(text)) {
                return true;
            }
        }
        return false;
    }

    private void report(boolean required, String message) {
        if (required) {
            fail(message);
        } else {
            out.println("warn  " + message);
        }
    }

    private void ok(String message) {
        out.println("ok    " + message);
    }

    private void fail(String message) {
        failures++;
        out.println("FAIL  " + message);
    }

    private static String rootMessage(Throwable e) {
        Throwable t = e;
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage();
    }

    private static String randomSecret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String redisRules() throws IOException {
        try (InputStream in = BrokerSetup.class.getResourceAsStream("redis-broker.rules")) {
            return new String(Objects.requireNonNull(in, "redis-broker.rules").readAllBytes(), StandardCharsets.UTF_8).strip();
        }
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static void writeSecret(Path file, String value) throws IOException {
        write(file, value, "rw-------");
    }

    /**
     * Read by the PostgreSQL or Redis container, which mounts only its own volume: owner and group may read, nobody else. The
     * container joins the group of the broker image (group_add in deploy/compose.yaml), so neither init nor the consumer needs root.
     */
    private static void writeShared(Path file, String value) throws IOException {
        write(file, value, "rw-r-----");
    }

    /** Created with its final mode and moved into place, so the content is never readable under a wider one. */
    private static void write(Path file, String value, String mode) throws IOException {
        FileAttribute<?>[] attributes = posix(file)
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(mode))}
                : new FileAttribute<?>[0];
        Path temp = Files.createTempFile(file.getParent(), "..", ".tmp", attributes);
        try {
            Files.writeString(temp, value);
            Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /** Redis takes {@code #<sha256 hex>} in place of {@code ><password>}, so the ACL file never holds the password. */
    static String sha256(String password) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean posix(Path path) {
        return path.getFileSystem().supportedFileAttributeViews().contains("posix");
    }

    private static void createSharedDirectory(Path directory) throws IOException {
        Files.createDirectories(directory);
        setMode(directory, "rwxr-x---");
    }

    private static void restrict(Path directory) throws IOException {
        setMode(directory, "rwx------");
    }

    private static void setMode(Path path, String mode) throws IOException {
        if (posix(path)) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(mode));
        }
    }
}
