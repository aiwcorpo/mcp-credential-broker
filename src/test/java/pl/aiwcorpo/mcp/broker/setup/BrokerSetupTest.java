package pl.aiwcorpo.mcp.broker.setup;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import pl.aiwcorpo.mcp.broker.support.TestPki;

/** First-start generation is done once and kept; what cannot be generated is reported with its cause. */
class BrokerSetupTest {

    private static final String STORE_PASSWORD = new String(TestPki.PASSWORD);
    private static final String CAPABILITIES_ALL = """
            {"data":{"secret/data/mcp/connections/probe":["create"],"secret/data/mcp/system-clients/probe":["create"],
            "secret/data/mcp/authenticators/probe":["create"],"secret/data/mcp/service-accounts/probe":["read"],
            "transit/encrypt/mcp-credential-broker":["update"],"transit/decrypt/mcp-authenticators":["update"]}}""";

    @TempDir
    Path dir;

    private final ByteArrayOutputStream output = new ByteArrayOutputStream();
    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    private BrokerSetup setup(Map<String, String> env) {
        return new BrokerSetup(env, dir, new PrintStream(output, true, StandardCharsets.UTF_8));
    }

    private String printed() {
        return output.toString(StandardCharsets.UTF_8);
    }

    @Test
    void generatesWhatTheOperatorDidNotSetAndKeepsItOnTheNextRun() throws Exception {
        setup(Map.of()).generate();
        Path env = dir.resolve("broker/env");
        String dbPassword = Files.readString(env.resolve("MCP_DB_PASSWORD"));
        String redisPassword = Files.readString(env.resolve("MCP_REDIS_PASSWORD"));

        assertThat(dbPassword).hasSizeGreaterThanOrEqualTo(43);
        assertThat(Files.readString(dir.resolve("postgres/password"))).isEqualTo(dbPassword);
        assertThat(Files.readString(dir.resolve("redis/users.acl")))
                .startsWith("user default off")
                .contains("user broker on #" + BrokerSetup.sha256(redisPassword) + " resetkeys ~broker:* ~jti:mcp-credential-broker:* resetchannels &credential.invalidated")
                .contains("+publish", "+eval", "+evalsha")
                .doesNotContain("+@all", "~*", redisPassword);
        assertThat(Files.readString(dir.resolve("redis/redis.conf")))
                .contains("aclfile /secrets/redis/users.acl", "maxmemory-policy noeviction", "appendonly yes");
        assertThat(Files.getPosixFilePermissions(dir.resolve("broker"))).isEqualTo(PosixFilePermissions.fromString("rwx------"));
        assertThat(Files.getPosixFilePermissions(env.resolve("MCP_DB_PASSWORD"))).isEqualTo(PosixFilePermissions.fromString("rw-------"));
        assertThat(Files.getPosixFilePermissions(dir.resolve("redis/users.acl"))).isEqualTo(PosixFilePermissions.fromString("rw-r-----"));
        assertThat(Files.getPosixFilePermissions(dir.resolve("postgres/password"))).isEqualTo(PosixFilePermissions.fromString("rw-r-----"));
        assertThat(Files.getPosixFilePermissions(dir.resolve("redis"))).isEqualTo(PosixFilePermissions.fromString("rwxr-x---"));
        try (var left = Files.list(env)) {
            assertThat(left).noneMatch(f -> f.getFileName().toString().startsWith("."));
        }

        setup(Map.of()).generate();
        assertThat(Files.readString(env.resolve("MCP_DB_PASSWORD"))).isEqualTo(dbPassword);
        assertThat(Files.readString(env.resolve("MCP_REDIS_PASSWORD"))).isEqualTo(redisPassword);
        assertThat(Files.readString(dir.resolve("redis/users.acl"))).contains("#" + BrokerSetup.sha256(redisPassword) + " ");
        assertThat(printed()).containsOnlyOnce("new   MCP_DB_PASSWORD").containsOnlyOnce("new   MCP_REDIS_PASSWORD");
    }

    @Test
    void sha256IsTheHexDigestRedisExpects() {
        assertThat(BrokerSetup.sha256("abc")).isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void theAclNamesTheAccountOfMcpRedisUser() throws Exception {
        setup(Map.of("MCP_REDIS_USER", "cb")).generate();

        assertThat(Files.readString(dir.resolve("redis/users.acl"))).contains("\nuser cb on #");
    }

    @Test
    void leavesAloneWhatTheOperatorSet() throws Exception {
        setup(Map.of("MCP_DB_PASSWORD", "own", "MCP_REDIS_PASSWORD", "own")).generate();

        assertThat(dir.resolve("broker/env/MCP_DB_PASSWORD")).doesNotExist();
        assertThat(dir.resolve("broker/env/MCP_REDIS_PASSWORD")).doesNotExist();
        assertThat(dir.resolve("postgres")).doesNotExist();
        assertThat(dir.resolve("redis")).doesNotExist();
    }

    @Test
    void namesEveryMissingSettingAndFails() {
        int exit = setup(Map.of("MCP_PORTAL_URL", "https://mcp.aiwcorpo.pl")).run();

        assertThat(exit).isEqualTo(1);
        assertThat(printed())
                .contains("FAIL  not set: MCP_OIDC_ISSUER, MCP_OIDC_JWKS_URI, MCP_BAO_ADDR, MCP_BAO_ROLE_ID, MCP_BAO_SECRET_ID")
                .contains("MCP_GATEWAY_JWKS_URI, MCP_GATEWAY_TLS_NAME")
                .doesNotContain("MCP_PORTAL_URL,")
                .doesNotContain("MCP_DB_PASSWORD,").doesNotContain("MCP_REDIS_PASSWORD,");
    }

    @Test
    void theGatewayKeysAsAFileNeedNoUriOrName() {
        Map<String, String> env = valid("https://127.0.0.1:1");
        env.remove("MCP_GATEWAY_JWKS_URI");
        env.remove("MCP_GATEWAY_TLS_NAME");
        env.put("MCP_GATEWAY_JWKS_FILE", dir.resolve("missing.jwks").toString());
        env.put("MCP_TLS_KEYSTORE", dir.resolve("missing.p12").toString());

        setup(env).run();

        assertThat(printed()).doesNotContain("not set:").contains("FAIL  certificate file " + dir.resolve("missing.p12"));

        env.put("MCP_GATEWAY_JWKS_URI", "https://mcp-gateway.internal:8443/jwks");
        output.reset();
        setup(env).run();
        assertThat(printed()).contains("FAIL  not set: only one of MCP_GATEWAY_JWKS_URI and MCP_GATEWAY_JWKS_FILE");
    }

    @Test
    void reportsMissingCertificateFiles() {
        Map<String, String> env = valid("https://127.0.0.1:1");
        env.put("MCP_TLS_KEYSTORE", dir.resolve("missing.p12").toString());

        int exit = setup(env).run();

        assertThat(exit).isEqualTo(1);
        assertThat(printed()).contains("FAIL  certificate file " + dir.resolve("missing.p12") + " does not exist");
    }

    @Test
    void anAddressWithoutTlsFailsUnlessPlainHttpIsAllowed() {
        Map<String, String> env = valid("http://127.0.0.1:1");
        env.put("MCP_TLS_KEYSTORE", dir.resolve("missing.p12").toString());

        setup(env).run();

        assertThat(printed()).contains("FAIL  MCP_OIDC_JWKS_URI http://127.0.0.1:1/certs must start with https://")
                .contains("FAIL  MCP_BAO_ADDR http://127.0.0.1:1 must start with https://");

        output.reset();
        env.put("MCP_ALLOW_PLAIN_HTTP", "true");
        setup(env).run();
        assertThat(printed()).doesNotContain("must start with https://");
    }

    @Test
    void theGatewayHostMustBeTheTlsName() {
        Map<String, String> env = valid("https://127.0.0.1:1");
        env.put("MCP_GATEWAY_JWKS_URI", "https://10.0.0.5:8443/.well-known/jwks.json");
        env.put("MCP_TLS_KEYSTORE", dir.resolve("missing.p12").toString());

        setup(env).run();

        assertThat(printed()).contains("FAIL  MCP_GATEWAY_JWKS_URI host 10.0.0.5 must equal MCP_GATEWAY_TLS_NAME mcp-gateway.internal");
    }

    @Test
    void aBffClientThatIsNoClientIdFailsTheCheck() {
        Map<String, String> env = valid("https://127.0.0.1:1");
        env.put("MCP_TLS_KEYSTORE", dir.resolve("missing.p12").toString());
        env.put("MCP_BFF_ALLOWED_AZP", "mcp-portal-bff, bad client");

        setup(env).run();

        assertThat(printed()).contains("FAIL  MCP_BFF_ALLOWED_AZP mcp-portal-bff, bad client must be client ids");
    }

    @Test
    void namesTheStorePasswordWhenItIsWrong() {
        TestPki pki = new TestPki("test-ca");
        Path keystore = TestPki.writeKeyStore(pki.server("mcp-credential-broker", "mcp-credential-broker.internal"), dir.resolve("keystore.p12"));
        Map<String, String> env = valid("https://127.0.0.1:1");
        env.put("MCP_TLS_KEYSTORE", keystore.toString());
        env.put("MCP_TLS_TRUSTSTORE", pki.writeTrustStore(dir.resolve("truststore.p12")).toString());
        env.put("MCP_TLS_STORE_PASSWORD", "wrong");

        setup(env).run();

        assertThat(printed()).contains("wrong MCP_TLS_STORE_PASSWORD");
    }

    @Test
    void aKeystoreWithoutAKeyAndAnEmptyTruststoreAreNamed() throws Exception {
        TestPki pki = new TestPki("test-ca");
        Path trustOnly = pki.writeTrustStore(dir.resolve("trust-only.p12"));
        Path empty = emptyStore(dir.resolve("empty.p12"));
        Map<String, String> env = valid("https://127.0.0.1:1");
        env.put("MCP_TLS_KEYSTORE", trustOnly.toString());
        env.put("MCP_TLS_TRUSTSTORE", trustOnly.toString());

        setup(env).run();
        assertThat(printed()).contains("FAIL  keystore " + trustOnly + " has no private key");

        output.reset();
        env.put("MCP_TLS_KEYSTORE", TestPki.writeKeyStore(pki.server("mcp-credential-broker"), dir.resolve("keystore.p12")).toString());
        env.put("MCP_TLS_TRUSTSTORE", empty.toString());
        setup(env).run();
        assertThat(printed()).contains("FAIL  truststore " + empty + " has no certificate");
    }

    @Test
    void passesWhenEverythingAnswersAndWarnsAboutTheGatewayOnly() throws Exception {
        Map<String, String> env = serverEnvironment(Map.of(
                "/certs", ok(jwks()),
                "/v1/auth/approle/login", ok("{\"auth\":{\"client_token\":\"s.token\",\"lease_duration\":3600}}"),
                "/v1/sys/capabilities-self", ok(CAPABILITIES_ALL)));

        int exit = setup(env).run();

        assertThat(exit).isZero();
        assertThat(printed())
                .contains("ok    identity provider keys ")
                .contains(": AppRole login works")
                .contains("ok    OpenBao policy covers the paths the broker uses")
                .contains("warn  gateway keys http://127.0.0.1:" + server.getAddress().getPort() + "/gateway/jwks: HTTP 404")
                .contains("Ready to start.")
                .doesNotContain("s.token");
    }

    @Test
    void aRefusedAppRoleLoginIsAFailureThatDoesNotEchoTheAnswer() throws Exception {
        Map<String, String> env = serverEnvironment(Map.of(
                "/certs", ok(jwks()),
                "/v1/auth/approle/login", answer(400, "{\"errors\":[\"invalid role or secret ID\"]}")));

        int exit = setup(env).run();

        assertThat(exit).isEqualTo(1);
        assertThat(printed()).contains("FAIL  OpenBao http://127.0.0.1:" + server.getAddress().getPort()
                + ": AppRole login refused (HTTP 400): MCP_BAO_ROLE_ID or MCP_BAO_SECRET_ID is wrong")
                .doesNotContain("invalid role");
    }

    @Test
    void aSealedOpenBaoIsNamed() throws Exception {
        Map<String, String> env = serverEnvironment(Map.of(
                "/certs", ok(jwks()),
                "/v1/auth/approle/login", answer(503, "{\"errors\":[\"Vault is sealed\"]}")));

        setup(env).run();

        assertThat(printed()).contains("OpenBao answered HTTP 503: it is sealed, not initialised, or not ready");
    }

    @Test
    void anIdentityProviderThatAnswersWithoutKeysFails() throws Exception {
        Map<String, String> env = serverEnvironment(Map.of(
                "/certs", ok("{\"keys\":[]}"),
                "/v1/auth/approle/login", ok("{\"auth\":{\"client_token\":\"s.token\"}}"),
                "/v1/sys/capabilities-self", ok(CAPABILITIES_ALL)));

        int exit = setup(env).run();

        assertThat(exit).isEqualTo(1);
        assertThat(printed()).contains("without keys; check MCP_OIDC_JWKS_URI");
    }

    @Test
    void anUnreachableIdentityProviderFailsAndAMissingPolicyOnlyWarns() throws Exception {
        Map<String, String> env = serverEnvironment(Map.of(
                "/v1/auth/approle/login", ok("{\"auth\":{\"client_token\":\"s.token\"}}"),
                "/v1/sys/capabilities-self", ok("{\"data\":{\"secret/data/mcp/connections/probe\":[\"create\"],"
                        + "\"transit/encrypt/mcp-credential-broker\":[\"deny\"]}}")));
        env.put("MCP_OIDC_JWKS_URI", "http://127.0.0.1:1/certs");

        int exit = setup(env).run();

        assertThat(exit).isEqualTo(1);
        assertThat(printed())
                .contains("FAIL  identity provider keys http://127.0.0.1:1/certs: connection refused")
                .contains("warn  OpenBao policy of the AppRole lacks: create on secret/data/mcp/authenticators/probe")
                .contains("update on transit/encrypt/mcp-credential-broker");
    }

    @Test
    void aRootTokenCoversEveryPath() throws Exception {
        Map<String, String> env = serverEnvironment(Map.of(
                "/certs", ok(jwks()),
                "/v1/auth/approle/login", ok("{\"auth\":{\"client_token\":\"s.token\"}}"),
                "/v1/sys/capabilities-self", ok("{\"secret/data/mcp/connections/probe\":[\"root\"],"
                        + "\"secret/data/mcp/system-clients/probe\":[\"root\"],\"secret/data/mcp/authenticators/probe\":[\"root\"],"
                        + "\"secret/data/mcp/service-accounts/probe\":[\"root\"],\"transit/encrypt/mcp-credential-broker\":[\"root\"],"
                        + "\"transit/decrypt/mcp-authenticators\":[\"root\"]}")));

        setup(env).run();

        assertThat(printed()).contains("ok    OpenBao policy covers the paths the broker uses");
    }

    @Test
    void trustsTheTruststoreOnlyAndNamesAnUntrustedCertificate() throws Exception {
        TestPki broker = new TestPki("broker-ca");
        TestPki other = new TestPki("other-ca");
        TestPki.Identity identity = other.server("idp", "localhost");
        HttpsServer https = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        https.setHttpsConfigurator(new HttpsConfigurator(serverContext(identity)));
        https.createContext("/certs", ok(jwks()));
        https.createContext("/v1/auth/approle/login", ok("{\"auth\":{\"client_token\":\"s.token\"}}"));
        https.createContext("/v1/sys/capabilities-self", ok(CAPABILITIES_ALL));
        https.start();
        try {
            String base = "https://localhost:" + https.getAddress().getPort();
            Map<String, String> env = valid(base);
            env.put("MCP_OIDC_JWKS_URI", base + "/certs");
            env.put("MCP_GATEWAY_JWKS_URI", base + "/gateway/jwks");
            env.put("MCP_GATEWAY_TLS_NAME", "localhost");
            env.put("MCP_TLS_KEYSTORE", TestPki.writeKeyStore(broker.server("mcp-credential-broker"), dir.resolve("keystore.p12")).toString());
            env.put("MCP_TLS_TRUSTSTORE", broker.writeTrustStore(dir.resolve("truststore.p12")).toString());

            assertThat(setup(env).run()).isEqualTo(1);
            assertThat(printed())
                    .contains("FAIL  identity provider keys " + base + "/certs: its certificate is not signed by a CA in MCP_TLS_OUTBOUND_TRUSTSTORE")
                    .contains("FAIL  OpenBao " + base + ": its certificate is not signed by a CA in MCP_TLS_OUTBOUND_TRUSTSTORE")
                    .contains("warn  gateway keys " + base + "/gateway/jwks: its certificate is not signed by");

            output.reset();
            env.put("MCP_TLS_TRUSTSTORE", other.writeTrustStore(dir.resolve("truststore-other.p12")).toString());
            assertThat(setup(env).run()).isZero();
            assertThat(printed()).contains("ok    identity provider keys " + base + "/certs").contains(": AppRole login works");

            // The outbound store alone decides the connections; the listener's store may keep only the CA of the callers.
            output.reset();
            env.put("MCP_TLS_TRUSTSTORE", broker.writeTrustStore(dir.resolve("truststore.p12")).toString());
            env.put("MCP_TLS_OUTBOUND_TRUSTSTORE", other.writeTrustStore(dir.resolve("outbound.p12")).toString());
            assertThat(setup(env).run()).isZero();
            assertThat(printed()).contains(", outbound truststore " + dir.resolve("outbound.p12"))
                    .contains("ok    identity provider keys " + base + "/certs");

            output.reset();
            env.put("MCP_TLS_OUTBOUND_TRUSTSTORE", " ");
            assertThat(setup(env).run()).isEqualTo(1);
            assertThat(printed()).contains("FAIL  MCP_TLS_OUTBOUND_TRUSTSTORE is empty");
        } finally {
            https.stop(0);
        }
    }

    @Test
    void translatesConnectionErrorsIntoLikelyCauses() {
        assertThat(BrokerSetup.cause(new IOException(new UnknownHostException("idp.corp")))).contains("does not resolve");
        assertThat(BrokerSetup.cause(new ConnectException())).contains("connection refused");
        ConnectException unresolved = new ConnectException();
        unresolved.initCause(new java.nio.channels.UnresolvedAddressException());
        assertThat(BrokerSetup.cause(unresolved)).contains("does not resolve");
        assertThat(BrokerSetup.cause(new SSLHandshakeException("PKIX path building failed"))).contains("MCP_TLS_TRUSTSTORE");
        assertThat(BrokerSetup.cause(new SSLHandshakeException("No subject alternative DNS name matching idp.corp found")))
                .contains("subjectAltName");
    }

    private Map<String, String> serverEnvironment(Map<String, HttpHandler> handlers) throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        handlers.forEach(server::createContext);
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        TestPki pki = new TestPki("test-ca");
        Map<String, String> env = valid(base);
        env.put("MCP_ALLOW_PLAIN_HTTP", "true");
        env.put("MCP_TLS_KEYSTORE", TestPki.writeKeyStore(pki.server("mcp-credential-broker", "mcp-credential-broker.internal"),
                dir.resolve("keystore.p12")).toString());
        env.put("MCP_TLS_TRUSTSTORE", pki.writeTrustStore(dir.resolve("truststore.p12")).toString());
        env.put("MCP_GATEWAY_JWKS_URI", base + "/gateway/jwks");
        env.put("MCP_GATEWAY_TLS_NAME", "127.0.0.1");
        return env;
    }

    /** A complete environment whose addresses all point at {@code base}. */
    private Map<String, String> valid(String base) {
        Map<String, String> env = new HashMap<>();
        BrokerSetup.REQUIRED.forEach(name -> env.put(name, "unused"));
        env.put("MCP_PORTAL_URL", "https://mcp.aiwcorpo.pl");
        env.put("MCP_OIDC_ISSUER", "https://idp.aiwcorpo.pl/realms/mcp");
        env.put("MCP_OIDC_JWKS_URI", base + "/certs");
        env.put("MCP_BAO_ADDR", base);
        env.put("MCP_TLS_STORE_PASSWORD", STORE_PASSWORD);
        env.put("MCP_GATEWAY_JWKS_URI", "https://mcp-gateway.internal:8443/.well-known/jwks.json");
        env.put("MCP_GATEWAY_TLS_NAME", "mcp-gateway.internal");
        return env;
    }

    private static String jwks() {
        try {
            return new JWKSet(new ECKeyGenerator(Curve.P_256).keyID("k1").generate()).toString(true);
        } catch (com.nimbusds.jose.JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static HttpHandler ok(String body) {
        return answer(200, body);
    }

    private static HttpHandler answer(int status, String body) {
        return (HttpExchange exchange) -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        };
    }

    private static SSLContext serverContext(TestPki.Identity identity) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("identity", identity.keys().getPrivate(), TestPki.PASSWORD,
                new X509Certificate[] {identity.certificate(), identity.issuer()});
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(store, TestPki.PASSWORD);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(factory.getKeyManagers(), null, null);
        return context;
    }

    private static Path emptyStore(Path file) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        try (OutputStream out = Files.newOutputStream(file)) {
            store.store(out, TestPki.PASSWORD);
        }
        return file;
    }
}
