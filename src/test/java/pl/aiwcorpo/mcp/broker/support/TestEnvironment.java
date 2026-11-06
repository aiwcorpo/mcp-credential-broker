package pl.aiwcorpo.mcp.broker.support;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.flywaydb.core.Flyway;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import com.sun.net.httpserver.HttpServer;

import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.system.SystemDefinition;
import pl.aiwcorpo.mcp.broker.system.SystemRepository;

/**
 * Dependencies of the broker for integration tests, started once per JVM: PostgreSQL, Redis with the same
 * ACL as the dev stack (explicit command list, prefixes, PUBLISH only), OpenBao in dev mode set up like
 * openbao/init.sh (KV v2, Transit key, AppRole with a narrow policy), a fake Jira whoami and IdP JWKS, and
 * a throwaway PKI.
 */
public final class TestEnvironment {

    public static final String REDIS_BROKER_PASSWORD = "test-only-redis-broker";
    public static final String REDIS_ADMIN_PASSWORD = "test-only-redis-admin";
    public static final String GITLAB_CLIENT_ID = "mcp-broker";
    public static final String GITLAB_CLIENT_SECRET = "test-only-gitlab-client-secret";
    public static final String EXCHANGE_CLIENT_ID = "mcp-credential-broker";
    public static final String EXCHANGE_CLIENT_SECRET = "test-only-exchange-client-secret";
    public static final String BAO_ROOT_TOKEN = "test-only-root";
    public static final String BAO_ROLE_ID = "test-only-role-id";
    public static final String BAO_SECRET_ID = "test-only-secret-id";

    /** PATs the fake Jira knows, as in the dev stack mock: &lt;login&gt;-pat belongs to &lt;login&gt;. */
    public static final Map<String, String> JIRA_PATS = Map.of(
            "alice-pat", "alice", "bob-pat", "bob", "carol-pat", "carol", "mallory-pat", "mallory");

    private static final String REDIS_DATA_COMMANDS = "-@all +get +set +setnx +getdel +getex +mget +del +unlink "
            + "+exists +expire +pexpire +ttl +pttl +incr +incrby +decr +hset +hget +hdel +hgetall +hexists +hincrby "
            + "+eval +evalsha +multi +exec +discard +ping +auth +hello +client|setname +client|setinfo +reset +quit";

    private static final String BAO_POLICY = """
            path "secret/data/mcp/connections/*"     { capabilities = ["create", "read", "update", "delete"] }
            path "secret/metadata/mcp/connections/*" { capabilities = ["read", "list", "delete"] }
            path "secret/data/mcp/system-clients/*"     { capabilities = ["create", "read", "update"] }
            path "secret/metadata/mcp/system-clients/*" { capabilities = ["read"] }
            path "secret/destroy/mcp/system-clients/*"  { capabilities = ["update"] }
            path "secret/data/mcp/system-clients-it/*"  { capabilities = ["read"] }
            path "secret/data/mcp/oauth-clients/*"      { capabilities = ["read"] }
            path "secret/data/mcp/service-accounts/*" { capabilities = ["read"] }
            path "transit/encrypt/mcp-credential-broker" { capabilities = ["update"] }
            path "transit/decrypt/mcp-credential-broker" { capabilities = ["update"] }
            path "secret/data/mcp/authenticators/*"     { capabilities = ["create", "read", "update", "delete"] }
            path "secret/metadata/mcp/authenticators/*" { capabilities = ["read", "list", "delete"] }
            path "transit/encrypt/mcp-authenticators" { capabilities = ["update"] }
            path "transit/decrypt/mcp-authenticators" { capabilities = ["update"] }
            """;

    private static TestEnvironment instance;

    public final PostgreSQLContainer postgres;
    public final GenericContainer<?> redis;
    public final GenericContainer<?> openbao;
    public final HttpServer upstream;
    public final HttpServer confluenceUpstream;
    public final SystemRepository systems;
    private final JdbcClient jdbc;
    public final AtomicInteger whoamiCalls = new AtomicInteger();
    public final AtomicInteger confluenceWhoamiCalls = new AtomicInteger();
    public final GitLabStub gitlab = new GitLabStub();
    public final IdpStub idp = new IdpStub();
    public final TestPki pki = new TestPki("mcp-test-ca");
    public final TestPki foreignPki = new TestPki("mcp-foreign-ca");
    public final TestTokens tokens = new TestTokens();
    public final Path workDir;

    public final TestPki.Identity gatewayClient = pki.client("mcp-gateway");
    public final TestPki.Identity bffClient = pki.client("mcp-portal-bff");
    public final TestPki.Identity offboardingClient = pki.client("mcp-offboarding");
    public final TestPki.Identity foreignGateway = foreignPki.client("mcp-gateway");

    public static synchronized TestEnvironment get() {
        if (instance == null) {
            instance = new TestEnvironment();
        }
        return instance;
    }

    private TestEnvironment() {
        try {
            workDir = Files.createTempDirectory("broker-it");
            TestPki.writeKeyStore(pki.server("mcp-credential-broker", "localhost", "mcp-credential-broker.internal"),
                    workDir.resolve("keystore.p12"));
            pki.writeTrustStore(workDir.resolve("truststore.p12"));
            Files.writeString(workDir.resolve("gateway-jwks.json"), Contracts.text(TestTokens.GATEWAY_JWKS_PATH));

            postgres = new PostgreSQLContainer(DockerImageName.parse("postgres:18.6-alpine"))
                    .withDatabaseName("broker").withUsername("broker").withPassword("test-only-db")
                    // Every cached Spring context and every broker JVM of MultiInstanceIntegrationTest holds a pool.
                    .withCommand("postgres", "-c", "max_connections=400");
            postgres.start();

            String acl = "user default off resetkeys resetchannels -@all\n"
                    + "user admin on >" + REDIS_ADMIN_PASSWORD + " ~* &* +@all\n"
                    + "user broker on >" + REDIS_BROKER_PASSWORD
                    + " resetkeys ~broker:* ~jti:mcp-credential-broker:* resetchannels &credential.invalidated "
                    + REDIS_DATA_COMMANDS + " +publish\n";
            redis = new GenericContainer<>(DockerImageName.parse("redis:8.8.4-alpine"))
                    .withCopyToContainer(Transferable.of(acl), "/etc/redis/users.acl")
                    .withCommand("redis-server", "--aclfile", "/etc/redis/users.acl", "--appendonly", "no")
                    .withExposedPorts(6379)
                    .waitingFor(Wait.forLogMessage(".*Ready to accept connections.*", 1));
            redis.start();

            openbao = new GenericContainer<>(DockerImageName.parse("openbao/openbao:2.7.2"))
                    .withCommand("server", "-dev", "-dev-listen-address=0.0.0.0:8200")
                    .withEnv("BAO_DEV_ROOT_TOKEN_ID", BAO_ROOT_TOKEN)
                    .withExposedPorts(8200)
                    .waitingFor(Wait.forHttp("/v1/sys/health").forStatusCode(200));
            openbao.start();
            configureOpenBao();

            upstream = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            upstream.createContext("/rest/api/2/myself", exchange -> {
                whoamiCalls.incrementAndGet();
                String auth = exchange.getRequestHeaders().getFirst("Authorization");
                String pat = auth != null && auth.startsWith("Bearer ") ? auth.substring(7) : null;
                int status;
                String body;
                if (pat == null || pat.startsWith("invalid")) {
                    status = 401;
                    body = "{\"errorMessages\":[\"You are not authenticated.\"],\"errors\":{}}";
                } else {
                    String user = JIRA_PATS.getOrDefault(pat, "someone-else");
                    status = 200;
                    body = "{\"key\":\"JIRAUSER-" + user + "\",\"name\":\"" + user + "\",\"emailAddress\":\"" + user
                            + "@corp.test\",\"displayName\":\"" + user + "\",\"active\":true}";
                }
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(status, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            upstream.createContext("/jwks", exchange -> {
                byte[] bytes = tokens.idpJwks().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            upstream.start();
            confluenceUpstream = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            confluenceUpstream.createContext("/rest/api/user/current", exchange -> {
                confluenceWhoamiCalls.incrementAndGet();
                String auth = exchange.getRequestHeaders().getFirst("Authorization");
                String pat = auth != null && auth.startsWith("Bearer ") ? auth.substring(7) : null;
                if (auth != null && auth.startsWith("Basic ")) {
                    // A Basic pair is "<login>:<token>"; the login is what whoami reports back, a token starting with invalid is refused.
                    String pair = new String(java.util.Base64.getDecoder().decode(auth.substring(6)), StandardCharsets.UTF_8);
                    int colon = pair.indexOf(':');
                    pat = pair.substring(colon + 1).startsWith("invalid") ? "invalid" : "basic-" + pair.substring(0, colon);
                }
                int status;
                String body;
                if (pat == null || pat.startsWith("invalid")) {
                    status = 401;
                    body = "{\"statusCode\":401,\"message\":\"\"}";
                } else {
                    String user = pat.startsWith("basic-") ? pat.substring(6) : JIRA_PATS.getOrDefault(pat, "someone-else");
                    status = 200;
                    body = "{\"type\":\"known\",\"username\":\"" + user + "\",\"userKey\":\"2c9" + user
                            + "\",\"displayName\":\"" + user + "\"}";
                }
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(status, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            confluenceUpstream.start();

            DriverManagerDataSource dataSource = new DriverManagerDataSource(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
            Flyway.configure().dataSource(dataSource).locations("classpath:db/migration").load().migrate();
            jdbc = JdbcClient.create(dataSource);
            systems = new SystemRepository(jdbc, Contracts.JSON);
            for (String id : List.of("jira", "confluence", "gitlab", "opensearch")) {
                putSystem(standardSystem(id));
            }
            requireOk(bao("POST", "secret/data/mcp/system-clients/gitlab", "{\"data\":{\"client_secret\":\"" + GITLAB_CLIENT_SECRET + "\"}}"));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String upstreamUrl() {
        return "http://127.0.0.1:" + upstream.getAddress().getPort();
    }

    public String openBaoUrl() {
        return "http://" + openbao.getHost() + ":" + openbao.getMappedPort(8200);
    }

    public String confluenceUrl() {
        return "http://127.0.0.1:" + confluenceUpstream.getAddress().getPort();
    }

    /** The systems every test starts with, stored the way the admin API stores them; the secrets are in OpenBao. */
    public SystemDefinition standardSystem(String id) {
        List<CredentialType> userSecret = List.of(CredentialType.USER_SECRET);
        return switch (id) {
            case "jira" -> new SystemDefinition("jira", URI.create(upstreamUrl()), "atlassian-dc", "jira", userSecret,
                    CredentialType.USER_SECRET, CredentialScheme.BEARER, null, null, null, null, null, null, SystemDefinition.newToken(),
                    SystemDefinition.newToken());
            case "confluence" -> new SystemDefinition("confluence", URI.create(confluenceUrl()), "atlassian-dc", "confluence", userSecret,
                    CredentialType.USER_SECRET, CredentialScheme.BEARER, null, null, null, null, null, null, SystemDefinition.newToken(),
                    SystemDefinition.newToken());
            case "gitlab" -> new SystemDefinition("gitlab", URI.create(gitlab.url()), "gitlab", null,
                    List.of(CredentialType.USER_OAUTH, CredentialType.USER_SECRET), CredentialType.USER_OAUTH, CredentialScheme.BEARER,
                    new SystemDefinition.Oauth(GITLAB_CLIENT_ID, URI.create("https://gitlab.test/oauth/authorize"),
                            URI.create(gitlab.url() + "/oauth/token"), null, List.of("read_api", "api")),
                    1, Duration.ofSeconds(1), null, null, null, SystemDefinition.newToken(), SystemDefinition.newToken());
            case "opensearch" -> new SystemDefinition("opensearch", URI.create(upstreamUrl()), "opensearch", null,
                    List.of(CredentialType.TOKEN_EXCHANGE), CredentialType.TOKEN_EXCHANGE, CredentialScheme.BEARER,
                    new SystemDefinition.Oauth(EXCHANGE_CLIENT_ID, URI.create(idp.tokenUrl()), URI.create(idp.tokenUrl()), null,
                            List.of("opensearch-audience")),
                    1, Duration.ofSeconds(2), "opensearch", null, null, SystemDefinition.newToken(), SystemDefinition.newToken());
            default -> throw new IllegalArgumentException(id);
        };
    }

    /** Replaces the stored system; running brokers see it within their sync interval. */
    public synchronized void putSystem(SystemDefinition system) {
        var existing = systems.find(system.id());
        // A test that replaces a system changes how it is configured, not where it points: grants stay valid.
        SystemDefinition next = existing.map(old -> system.withClientRevision(old.clientRevision())).orElse(system)
                .withEtag(SystemDefinition.newToken());
        if (existing.isEmpty()) {
            systems.insert(next, java.time.Instant.now());
        } else if (!systems.update(next, existing.get().etag(), java.time.Instant.now())) {
            throw new IllegalStateException("system " + system.id() + " changed while a test replaced it");
        }
    }

    public synchronized void resetSystem(String id) {
        putSystem(standardSystem(id));
    }

    public synchronized void removeSystem(String id) {
        jdbc.sql("delete from connection where system = :system").param("system", id).update();
        systems.delete(id);
    }

    /** The test brokers poll every 200 ms; waiting three polls makes a change visible to all of them. */
    public void awaitSystemSync() {
        try {
            Thread.sleep(700);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    public SystemDefinition withTimeout(SystemDefinition system, Duration timeout) {
        return system.withTimeout(timeout);
    }

    /** Service Desk as service-account; not among the standard systems, so that other tests have an unconfigured one. */
    public SystemDefinition serviceDesk() {
        return new SystemDefinition("servicedesk", URI.create(upstreamUrl()), "generic-rest", null, List.of(CredentialType.SERVICE_ACCOUNT),
                CredentialType.SERVICE_ACCOUNT, CredentialScheme.BEARER, null, null, null, null, null, null, SystemDefinition.newToken(),
                SystemDefinition.newToken());
    }

    public void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("MCP_TLS_KEYSTORE", () -> workDir.resolve("keystore.p12").toString());
        registry.add("MCP_TLS_TRUSTSTORE", () -> workDir.resolve("truststore.p12").toString());
        registry.add("MCP_TLS_STORE_PASSWORD", () -> new String(TestPki.PASSWORD));
        registry.add("MCP_BROKER_PORT", () -> "0");
        registry.add("MCP_DB_URL", postgres::getJdbcUrl);
        registry.add("MCP_DB_USER", postgres::getUsername);
        registry.add("MCP_DB_PASSWORD", postgres::getPassword);
        registry.add("MCP_REDIS_HOST", redis::getHost);
        registry.add("MCP_REDIS_PORT", () -> String.valueOf(redis.getMappedPort(6379)));
        registry.add("MCP_REDIS_USER", () -> "broker");
        registry.add("MCP_REDIS_PASSWORD", () -> REDIS_BROKER_PASSWORD);
        registry.add("MCP_BAO_ADDR", this::openBaoUrl);
        registry.add("MCP_BAO_ROLE_ID", () -> BAO_ROLE_ID);
        registry.add("MCP_BAO_SECRET_ID", () -> BAO_SECRET_ID);
        registry.add("MCP_OIDC_ISSUER", () -> TestTokens.IDP_ISSUER);
        registry.add("MCP_OIDC_JWKS_URI", () -> upstreamUrl() + "/jwks");
        registry.add("MCP_GATEWAY_JWKS_FILE", () -> workDir.resolve("gateway-jwks.json").toString());
        registry.add("MCP_ALLOW_TEST_KEYS", () -> "true");
        registry.add("broker.system-sync.interval", () -> "200ms");
        registry.add("broker.bff-token.token-url", idp::tokenUrl);
        registry.add("broker.bff-token.mfa-acr-values", () -> "urn:test:mfa");
        registry.add("broker.oauth-flow.sweep-interval", () -> "PT1H");
        registry.add("broker.oauth-flow.refresh-lock-wait", () -> "3s");
        registry.add("MCP_PORTAL_URL", () -> "https://mcp-portal.test");
        registry.add("MCP_ALLOW_PLAIN_HTTP", () -> "true");
    }

    /** Raw OpenBao call with the root token, for setup and for checking what is stored. */
    public HttpResponse<String> bao(String method, String path, String body) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(openBaoUrl() + "/v1/" + path))
                .header("X-Vault-Token", BAO_ROOT_TOKEN)
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        try {
            return HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private void configureOpenBao() {
        requireOk(bao("POST", "sys/mounts/transit", "{\"type\":\"transit\"}"));
        requireOk(bao("POST", "transit/keys/mcp-credential-broker", "{\"type\":\"aes256-gcm96\"}"));
        requireOk(bao("POST", "transit/keys/mcp-authenticators", "{\"type\":\"aes256-gcm96\"}"));
        requireOk(bao("PUT", "sys/policies/acl/mcp-credential-broker",
                Contracts.JSON.createObjectNode().put("policy", BAO_POLICY).toString()));
        requireOk(bao("POST", "secret/data/mcp/system-clients/opensearch",
                "{\"data\":{\"client_id\":\"" + EXCHANGE_CLIENT_ID + "\",\"client_secret\":\"" + EXCHANGE_CLIENT_SECRET + "\"}}"));
        requireOk(bao("POST", "sys/auth/approle", "{\"type\":\"approle\"}"));
        requireOk(bao("POST", "auth/approle/role/mcp-credential-broker",
                "{\"token_policies\":\"mcp-credential-broker\",\"token_ttl\":\"1h\",\"token_max_ttl\":\"4h\"}"));
        requireOk(bao("POST", "auth/approle/role/mcp-credential-broker/role-id", "{\"role_id\":\"" + BAO_ROLE_ID + "\"}"));
        requireOk(bao("POST", "auth/approle/role/mcp-credential-broker/custom-secret-id",
                "{\"secret_id\":\"" + BAO_SECRET_ID + "\"}"));
    }

    private static void requireOk(HttpResponse<String> response) {
        if (response.statusCode() >= 300) {
            throw new IllegalStateException("OpenBao setup failed: HTTP " + response.statusCode() + " " + response.body());
        }
    }
}
