package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import com.sun.net.httpserver.HttpServer;

import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.BrokerProcess;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.GitLabStub;
import pl.aiwcorpo.mcp.broker.support.InvalidationListener;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/** C4 {@code /v1/admin/systems}: the portal BFF with the token of an administrator, over real mTLS against PostgreSQL, Redis and OpenBao. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class SystemAdminIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final Set<String> STANDARD = Set.of("jira", "confluence", "gitlab", "opensearch");
    private static final String SECRET = "test-only-system-client-secret-0001";
    private static final int PORT_SECOND_INSTANCE = 18718;
    private static final int PORT_STALE_INSTANCE = 18719;
    private static final int PORT_STRICT_INSTANCE = 18710;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @LocalServerPort
    int port;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    SystemRegistry registry;

    BrokerClient bff;
    BrokerClient gateway;
    final TestTokens tokens = env.tokens;
    final GitLabStub gitlab = env.gitlab;
    final String adminSub = UUID.randomUUID().toString();
    final List<HttpServer> servers = new ArrayList<>();

    @BeforeEach
    void clients() {
        bff = new BrokerClient(env.pki.clientContext(env.bffClient), port);
        gateway = new BrokerClient(env.pki.clientContext(env.gatewayClient), port);
        gitlab.revokeAccepts();
    }

    @AfterEach
    void removeWhatTheTestCreated() {
        servers.forEach(server -> server.stop(0));
        servers.clear();
        jdbc.sql("delete from connection where system not in ('jira', 'confluence', 'gitlab', 'opensearch')").update();
        for (var system : env.systems.findAll()) {
            if (!STANDARD.contains(system.id())) {
                env.systems.delete(system.id());
            }
        }
        registry.reload();
    }

    @AfterAll
    static void letOtherBrokersSeeTheCleanup() {
        env.awaitSystemSync();
    }

    private static String newId() {
        return "n" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
    }

    // Bodies and calls ------------------------------------------------------------------------------------

    private ObjectNode gitlabBody(String secret) {
        ObjectNode body = Contracts.JSON.createObjectNode();
        body.put("baseUrl", gitlab.url()).put("adapter", "gitlab");
        body.putArray("supportedTypes").add("user-oauth").add("user-secret");
        body.put("defaultType", "user-oauth").put("secretScheme", "Bearer");
        ObjectNode oauth = body.putObject("oauth");
        oauth.put("clientId", "client-one");
        if (secret != null) {
            oauth.put("clientSecret", secret);
        }
        oauth.put("authorizeUrl", "https://gitlab.test/oauth/authorize").put("tokenUrl", gitlab.url() + "/oauth/token");
        oauth.putArray("scopes").add("read_api");
        return body;
    }

    private ObjectNode jiraBody(String baseUrl) {
        ObjectNode body = Contracts.JSON.createObjectNode();
        body.put("baseUrl", baseUrl).put("adapter", "atlassian-dc").put("product", "jira");
        body.putArray("supportedTypes").add("user-secret");
        body.put("defaultType", "user-secret").put("secretScheme", "Bearer");
        return body;
    }

    private BrokerClient.Response put(String id, ObjectNode body, Map<String, String> headers) {
        return put(id, body, headers, tokens.bffAdmin(adminSub, "root"));
    }

    private BrokerClient.Response put(String id, ObjectNode body, Map<String, String> headers, String token) {
        return bff.send("PUT", "/v1/admin/systems/" + id, token, TestTokens.newRequestId(), body.toString(), headers);
    }

    private BrokerClient.Response create(String id, ObjectNode body) {
        return put(id, body, Map.of("If-None-Match", "*"));
    }

    private BrokerClient.Response replace(String id, ObjectNode body, String etag) {
        return put(id, body, Map.of("If-Match", etag));
    }

    private BrokerClient.Response get(String id) {
        return bff.send("GET", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), TestTokens.newRequestId(), null);
    }

    private BrokerClient.Response delete(String id, String etag) {
        return bff.send("DELETE", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), TestTokens.newRequestId(), null,
                etag == null ? Map.of() : Map.of("If-Match", etag));
    }

    private BrokerClient.Response deleteCurrent(String id) {
        return delete(id, get(id).header("ETag"));
    }

    private BrokerClient.Response list() {
        return bff.send("GET", "/v1/admin/systems", tokens.bffAdmin(adminSub, "root"), TestTokens.newRequestId(), null);
    }

    private JsonNode storedSecret(String id, int version) {
        var response = env.bao("GET", "secret/data/mcp/system-clients/" + id + "?version=" + version, null);
        return response.statusCode() == 200 ? Contracts.JSON.readTree(response.body()).path("data").path("data") : null;
    }

    private Integer secretVersionOf(String id) {
        return jdbc.sql("select secret_version from target_system where id = :id").param("id", id).query(Integer.class).single();
    }

    private String connectUserSecret(String id, String sub, String pat) {
        BrokerClient.Response connected = bff.send("PUT", "/v1/connections/" + id + "/secret", tokens.bffUser(sub, "alice"), null,
                "{\"secret\":\"" + pat + "\"}");
        assertThat(connected.status()).isEqualTo(200);
        return jdbc.sql("select secret_version from connection where sub = :sub and system = :system")
                .param("sub", sub).param("system", id).query(String.class).single();
    }

    private GitLabStub.Grant connectOauth(String id, String sub, int expiresInSeconds) {
        BrokerClient.Response started = bff.send("POST", "/v1/connections/" + id + "/oauth/start", tokens.bffUser(sub, "alice"), null,
                "{\"returnPath\":\"/catalog\"}");
        assertThat(started.status()).isEqualTo(200);
        GitLabStub.Grant grant = gitlab.issueCode("alice", expiresInSeconds);
        BrokerClient.Response completed = complete(id, sub, started, grant.code());
        assertThat(completed.status()).isEqualTo(200);
        return grant;
    }

    private BrokerClient.Response complete(String id, String sub, BrokerClient.Response started, String code) {
        String state = null;
        for (String pair : URI.create(started.json().path("authorizeUrl").stringValue()).getRawQuery().split("&")) {
            if (pair.startsWith("state=")) {
                state = URLDecoder.decode(pair.substring(6), StandardCharsets.UTF_8);
            }
        }
        return bff.send("POST", "/v1/connections/" + id + "/oauth/complete", tokens.bffUser(sub, "alice"), null,
                "{\"flowId\":\"" + started.json().path("flowId").stringValue() + "\",\"code\":\"" + code + "\",\"state\":\"" + state + "\"}");
    }

    private long rows(String system) {
        return jdbc.sql("select count(*) from connection where system = :system").param("system", system).query(Long.class).single();
    }

    private String connectionStatus(String sub, String id) {
        JsonNode listed = bff.send("GET", "/v1/connections", tokens.bffUser(sub, "alice"), null, null).json();
        for (JsonNode connection : listed) {
            if (id.equals(connection.path("system").stringValue())) {
                return connection.path("status").stringValue();
            }
        }
        return null;
    }

    private BrokerClient.Response resolve(String sub, String id) {
        String rid = TestTokens.newRequestId();
        return gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", rid), rid, "{\"system\":\"" + id + "\"}");
    }

    /** A backend that answers whoami for every PAT and counts every request it gets. */
    private final class Recorder {
        final HttpServer server;
        final AtomicInteger requests = new AtomicInteger();

        Recorder() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                requests.incrementAndGet();
                byte[] body = "{\"name\":\"alice\",\"emailAddress\":\"alice@corp.test\"}".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
            server.start();
            servers.add(server);
        }

        String url() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }
    }

    // CRUD ------------------------------------------------------------------------------------------------

    @Test
    void aSystemIsCreatedReadReplacedAndDeletedOverHttp() {
        String id = newId();
        BrokerClient.Response created = create(id, gitlabBody(SECRET));
        assertThat(created.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("SystemAdminView", created.json())).isEmpty();
        assertThat(created.json().path("system").stringValue()).isEqualTo(id);
        assertThat(created.json().path("oauth").path("clientSecretSet").booleanValue()).isTrue();
        String etag = created.header("ETag");
        assertThat(etag).matches("^\"[A-Za-z0-9_-]{8,128}\"$");

        BrokerClient.Response read = get(id);
        assertThat(read.status()).isEqualTo(200);
        assertThat(read.header("ETag")).isEqualTo(etag);
        assertThat(read.json()).isEqualTo(created.json());

        JsonNode listed = list().json();
        assertThat(listed.valueStream().map(system -> system.path("system").stringValue()).toList())
                .contains(id, "jira", "gitlab").isSorted();
        for (JsonNode system : listed) {
            assertThat(Contracts.brokerSchemaErrors("SystemAdminView", system)).isEmpty();
        }

        String rid = TestTokens.newRequestId();
        BrokerClient.Response readers = gateway.send("GET", "/v1/systems", tokens.gatewayService(rid), rid, null);
        assertThat(readers.json().valueStream().filter(system -> id.equals(system.path("system").stringValue())).findFirst())
                .hasValueSatisfying(system -> {
                    assertThat(Contracts.brokerSchemaErrors("SystemInfo", system)).isEmpty();
                    assertThat(system.path("supportedTypes").valueStream().map(JsonNode::stringValue).toList())
                            .containsExactly("user-oauth", "user-secret");
                    assertThat(system.path("oauthScopes").valueStream().map(JsonNode::stringValue).toList()).containsExactly("read_api");
                });

        ObjectNode changed = gitlabBody(null);
        ((ObjectNode) changed.path("oauth")).putArray("scopes").add("read_api").add("api");
        BrokerClient.Response replaced = replace(id, changed, etag);
        assertThat(replaced.status()).isEqualTo(200);
        assertThat(replaced.header("ETag")).isNotEqualTo(etag);
        assertThat(replaced.json().path("oauth").path("scopes").size()).isEqualTo(2);
        assertThat(replaced.json().path("oauth").path("clientSecretSet").booleanValue()).as("kept").isTrue();

        int version = secretVersionOf(id);
        assertThat(deleteCurrent(id).status()).isEqualTo(204);
        assertThat(get(id).status()).isEqualTo(404);
        assertThat(registry.find(id)).isEmpty();
        assertThat(storedSecret(id, version)).as("the version the row pointed at is destroyed").isNull();
    }

    @Test
    void theFieldsOfTheContractRoundTrip() {
        String id = newId();
        ObjectNode body = gitlabBody(SECRET);
        body.put("revokeUrl", gitlab.url() + "/oauth/revoke").put("timeout", "PT30S").put("userSecretScheme", "Basic");
        BrokerClient.Response created = create(id, body);
        assertThat(created.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("SystemAdminView", created.json())).isEmpty();
        assertThat(created.json().path("revokeUrl").stringValue()).isEqualTo(gitlab.url() + "/oauth/revoke");
        assertThat(created.json().path("timeout").stringValue()).isEqualTo("PT30S");
        assertThat(created.json().path("userSecretScheme").stringValue()).isEqualTo("Basic");
        assertThat(get(id).json()).isEqualTo(created.json());

        ObjectNode badTimeout = gitlabBody(SECRET);
        badTimeout.put("timeout", "PT20M");
        assertThat(create(newId(), badTimeout).status()).as("more than 10 minutes").isEqualTo(400);
        badTimeout.put("timeout", "30s");
        assertThat(create(newId(), badTimeout).status()).as("not ISO 8601").isEqualTo(400);
    }

    @Test
    void preconditionsAreEnforced() {
        String id = newId();
        assertThat(put(id, gitlabBody(SECRET), Map.of()).status()).as("neither header").isEqualTo(428);
        assertThat(replace(id, gitlabBody(SECRET), "\"Zx8Tq2LmWk93vNpA\"").status()).as("replace of a system that is not there").isEqualTo(412);
        BrokerClient.Response created = create(id, gitlabBody(SECRET));
        assertThat(created.status()).isEqualTo(200);
        String etag = created.header("ETag");

        BrokerClient.Response again = create(id, gitlabBody(SECRET));
        assertThat(again.status()).as("create of an existing system").isEqualTo(412);
        assertThat(again.body()).isEqualTo("{\"error\":\"precondition_failed\"}");

        assertThat(replace(id, gitlabBody(null), "\"Zx8Tq2LmWk93vNpA\"").status()).as("stale etag").isEqualTo(412);
        BrokerClient.Response first = replace(id, gitlabBody(null), etag);
        assertThat(first.status()).isEqualTo(200);
        assertThat(replace(id, gitlabBody(null), etag).status()).as("the etag was spent by the first write").isEqualTo(412);
        assertThat(replace(id, gitlabBody(null), "not-an-etag").status()).isEqualTo(400);
        assertThat(put(id, gitlabBody(null), Map.of("If-Match", etag, "If-None-Match", "*")).status()).isEqualTo(400);
        assertThat(get(id).header("ETag")).isEqualTo(first.header("ETag"));

        assertThat(delete(id, null).status()).as("a delete needs If-Match too").isEqualTo(428);
        assertThat(delete(id, etag).status()).as("stale etag").isEqualTo(412);
        assertThat(get(id).status()).isEqualTo(200);
        assertThat(delete(id, first.header("ETag")).status()).isEqualTo(204);
    }

    @Test
    void malformedInputIs400AndAWellFormedUnknownIdIs404() {
        String unknown = newId();
        String wellFormedEtag = "\"Zx8Tq2LmWk93vNpA\"";
        for (String malformed : List.of("Bad_Id", "a", "UPPER", "has-dash", "x".repeat(40))) {
            assertThat(get(malformed).status()).as("GET " + malformed).isEqualTo(400);
            assertThat(delete(malformed, wellFormedEtag).status()).as("DELETE " + malformed).isEqualTo(400);
            assertThat(bff.send("DELETE", "/v1/admin/systems/" + malformed, tokens.bffAdmin(adminSub, "root"), null, null).status())
                    .as("DELETE without If-Match " + malformed).isEqualTo(400);
            assertThat(replace(malformed, gitlabBody(SECRET), wellFormedEtag).status()).as("PUT " + malformed).isEqualTo(400);
        }
        assertThat(get(unknown).status()).isEqualTo(404);
        assertThat(delete(unknown, null).status()).as("a delete of a system that is not there").isEqualTo(204);
        assertThat(delete(unknown, wellFormedEtag).status()).isEqualTo(204);
        assertThat(replace(unknown, gitlabBody(SECRET), wellFormedEtag).status()).as("a well-formed etag for nothing").isEqualTo(412);

        for (String badEtag : List.of("abc", "\"short\"", "W/\"Zx8Tq2LmWk93vNpA\"", "Zx8Tq2LmWk93vNpA", "\"has space in it\"", "*", "\"\"")) {
            assertThat(replace(unknown, gitlabBody(SECRET), badEtag).status()).as("PUT If-Match " + badEtag).isEqualTo(400);
            assertThat(delete(unknown, badEtag).status()).as("DELETE If-Match " + badEtag + " on a system that is not there").isEqualTo(400);
        }
        for (String badNoneMatch : List.of("abc", "\"Zx8Tq2LmWk93vNpA\"", "**", "")) {
            assertThat(put(unknown, gitlabBody(SECRET), Map.of("If-None-Match", badNoneMatch)).status())
                    .as("PUT If-None-Match '" + badNoneMatch + "'").isEqualTo(400);
        }
        BrokerClient.Response created = create(unknown, gitlabBody(SECRET));
        assertThat(created.status()).isEqualTo(200);
        assertThat(replace(unknown, gitlabBody(null), "not-an-etag").status()).isEqualTo(400);
        assertThat(replace(unknown, gitlabBody(null), wellFormedEtag).status()).as("well-formed but stale").isEqualTo(412);
        assertThat(delete(unknown, wellFormedEtag).status()).as("well-formed but stale").isEqualTo(412);
        assertThat(delete(unknown, "garbage").status()).isEqualTo(400);
        assertThat(get(unknown).status()).as("nothing of this changed it").isEqualTo(200);
    }

    @Test
    void aSystemMayHaveADisplayNameAndTheAdminViewAlwaysHasOne() {
        String plain = newId();
        BrokerClient.Response withoutName = create(plain, gitlabBody(SECRET));
        assertThat(withoutName.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("SystemAdminView", withoutName.json())).isEmpty();
        assertThat(withoutName.json().path("displayName").stringValue()).as("the id when none is given").isEqualTo(plain);
        assertThat(get(plain).json().path("displayName").stringValue()).isEqualTo(plain);

        String named = newId();
        ObjectNode body = jiraBody(env.upstreamUrl());
        body.put("displayName", "Jira (Nowy Sacz) \u0142\u00f3d\u017a");
        BrokerClient.Response created = create(named, body);
        assertThat(created.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("SystemAdminView", created.json())).isEmpty();
        assertThat(created.json().path("displayName").stringValue()).isEqualTo("Jira (Nowy Sacz) \u0142\u00f3d\u017a");
        assertThat(list().json().valueStream().filter(system -> named.equals(system.path("system").stringValue())).findFirst())
                .hasValueSatisfying(system -> assertThat(system.path("displayName").stringValue()).startsWith("Jira"));

        String rid = TestTokens.newRequestId();
        Map<String, JsonNode> readers = systemsOf(gateway);
        assertThat(readers.get(named).path("displayName").stringValue()).isEqualTo("Jira (Nowy Sacz) \u0142\u00f3d\u017a");
        assertThat(readers.get(plain).has("displayName")).as("SystemInfo carries it only when set").isFalse();
        for (JsonNode system : readers.values()) {
            assertThat(Contracts.brokerSchemaErrors("SystemInfo", system)).isEmpty();
        }
        assertThat(rid).isNotNull();

        ObjectNode renamed = jiraBody(env.upstreamUrl());
        BrokerClient.Response replaced = replace(named, renamed, created.header("ETag"));
        assertThat(replaced.status()).isEqualTo(200);
        assertThat(replaced.json().path("displayName").stringValue()).as("a replace without it clears it").isEqualTo(named);
        assertThat(systemsOf(gateway).get(named).has("displayName")).isFalse();

        ObjectNode longest = jiraBody(env.upstreamUrl());
        longest.put("displayName", "n".repeat(64));
        assertThat(create(newId(), longest).status()).isEqualTo(200);
    }

    @Test
    void aDisplayNameIsOneToSixtyFourCharactersWithoutControlOrFormatCharacters() {
        for (String bad : List.of("", "n".repeat(65), "tab\there", "bell\u0007", "new\nline", "zero\u200bwidth", "bidi\u202eflip",
                "bom\ufeff", "line\u2028sep", "para\u2029sep")) {
            ObjectNode body = jiraBody(env.upstreamUrl());
            body.put("displayName", bad);
            assertThat(create(newId(), body).status()).as("'" + bad.replace("\n", "\\n") + "'").isEqualTo(400);
        }
        assertThat(env.systems.findAll()).extracting(system -> system.id()).containsExactlyInAnyOrderElementsOf(STANDARD);
    }

    @Test
    void reservedAndMalformedIdsAreRefused() {
        for (String reserved : List.of("gateway", "offboarding", "portal", "broker", "prometheus", "platform", "admin", "registry",
                "adapter", "internal", "ci")) {
            BrokerClient.Response response = create(reserved, gitlabBody(SECRET));
            assertThat(response.status()).as(reserved).isEqualTo(422);
            assertThat(Contracts.brokerSchemaErrors("SystemRejected", response.json())).isEmpty();
            assertThat(response.json().path("reason").stringValue()).isEqualTo("system_reserved");
            assertThat(get(reserved).status()).as("it does not match the pattern of a system id").isEqualTo(400);
            assertThat(delete(reserved, "\"Zx8Tq2LmWk93vNpA\"").status()).isEqualTo(400);
        }
        for (String malformed : List.of("Notes", "a", "1abc", "has-dash", "x".repeat(32))) {
            assertThat(create(malformed, gitlabBody(SECRET)).status()).as(malformed).isEqualTo(400);
        }
        assertThat(env.systems.findAll()).extracting(system -> system.id()).containsExactlyInAnyOrderElementsOf(STANDARD);
    }

    // Secrets ---------------------------------------------------------------------------------------------

    @Test
    void theClientSecretIsStoredInItsOwnPathAndNeverReturnedOrLogged(CapturedOutput output) {
        String id = newId();
        String rid = TestTokens.newRequestId();
        BrokerClient.Response created = bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), rid,
                gitlabBody(SECRET).toString(), Map.of("If-None-Match", "*"));
        assertThat(created.status()).isEqualTo(200);

        assertThat(created.body()).doesNotContain(SECRET).doesNotContain("clientSecret\"");
        assertThat(get(id).body()).doesNotContain(SECRET);
        assertThat(list().body()).doesNotContain(SECRET);
        assertThat(secretVersionOf(id)).isEqualTo(1);
        assertThat(storedSecret(id, 1).path("client_secret").stringValue()).isEqualTo(SECRET);
        assertThat(env.bao("GET", "secret/data/mcp/oauth-clients/" + id, null).statusCode()).as("not the path of 1.x").isEqualTo(404);
        assertThat(jdbc.sql("select cast(t as text) from target_system t where id = :id").param("id", id).query(String.class).single())
                .as("not in the table").doesNotContain(SECRET);
        assertThat(output.getAll()).doesNotContain(SECRET);
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> assertThat(event.toString()).doesNotContain(SECRET));
    }

    @Test
    void aRotationWritesANewVersionDestroysTheOldOneAndPinsTheRow() {
        String id = newId();
        BrokerClient.Response created = create(id, gitlabBody(SECRET));
        assertThat(secretVersionOf(id)).isEqualTo(1);

        String rotated = "test-only-rotated-client-secret-0002";
        BrokerClient.Response second = replace(id, gitlabBody(rotated), created.header("ETag"));
        assertThat(second.status()).isEqualTo(200);

        assertThat(secretVersionOf(id)).isEqualTo(2);
        assertThat(storedSecret(id, 2).path("client_secret").stringValue()).isEqualTo(rotated);
        assertThat(storedSecret(id, 1)).as("nothing points at it any more").isNull();

        BrokerClient.Response kept = replace(id, gitlabBody(null), second.header("ETag"));
        assertThat(kept.status()).isEqualTo(200);
        assertThat(secretVersionOf(id)).as("no secret given, no new version").isEqualTo(2);
    }

    @Test
    void concurrentChangesNeverCombineTheSecretOfOneWithTheConfigurationOfTheOther() throws Exception {
        String id = newId();
        String etag = create(id, gitlabBody(SECRET)).header("ETag");
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            for (int round = 0; round < 6; round++) {
                ObjectNode a = gitlabBody("secret-of-a-" + round);
                ((ObjectNode) a.path("oauth")).put("clientId", "client-a-" + round);
                ObjectNode b = gitlabBody("secret-of-b-" + round);
                ((ObjectNode) b.path("oauth")).put("clientId", "client-b-" + round);
                CountDownLatch go = new CountDownLatch(1);
                String base = etag;
                Future<BrokerClient.Response> first = pool.submit(() -> {
                    go.await();
                    return replace(id, a, base);
                });
                Future<BrokerClient.Response> second = pool.submit(() -> {
                    go.await();
                    return replace(id, b, base);
                });
                go.countDown();
                BrokerClient.Response one = first.get();
                BrokerClient.Response two = second.get();

                assertThat(List.of(one.status(), two.status())).as("round " + round).containsExactlyInAnyOrder(200, 412);
                BrokerClient.Response winner = one.status() == 200 ? one : two;
                String letter = one.status() == 200 ? "a" : "b";
                etag = winner.header("ETag");
                assertThat(get(id).json().path("oauth").path("clientId").stringValue()).isEqualTo("client-" + letter + "-" + round);
                int pinned = secretVersionOf(id);
                assertThat(storedSecret(id, pinned).path("client_secret").stringValue()).as("round " + round)
                        .isEqualTo("secret-of-" + letter + "-" + round);
                JsonNode versions = Contracts.JSON.readTree(env.bao("GET", "secret/metadata/mcp/system-clients/" + id, null).body())
                        .path("data").path("versions");
                List<String> alive = new ArrayList<>();
                for (String name : versions.propertyNames()) {
                    if (!versions.path(name).path("destroyed").booleanValue()) {
                        alive.add(name);
                    }
                }
                assertThat(alive).as("only the pinned version is left, the loser destroyed its own").containsExactly(String.valueOf(pinned));
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void theAdapterReadsTheVersionTheRowPointsAtEvenWhenAnotherVersionExists() {
        String id = newId();
        create(id, gitlabBody(SECRET));
        int pinned = secretVersionOf(id);
        assertThat(env.bao("POST", "secret/data/mcp/system-clients/" + id,
                "{\"data\":{\"client_secret\":\"written-behind-the-back-of-the-row\"}}").statusCode()).isEqualTo(200);

        String sub = UUID.randomUUID().toString();
        connectOauth(id, sub, 7200);

        assertThat(gitlab.tokenRequests().stream().filter(form -> sub.length() > 0 && SECRET.equals(form.get("client_secret"))).toList())
                .as("the token request carried the secret of the pinned version").isNotEmpty();
        assertThat(gitlab.tokenRequests()).noneMatch(form -> "written-behind-the-back-of-the-row".equals(form.get("client_secret")));
        assertThat(pinned).isEqualTo(1);
    }

    @Test
    void aSecretIsRequiredWhenAnAddressOrTheClientChanges() {
        String id = newId();
        assertThat(create(id, gitlabBody(null)).json().path("reason").stringValue())
                .as("a new system has no secret to keep").isEqualTo("client_secret_required");
        BrokerClient.Response created = create(id, gitlabBody(SECRET));
        assertThat(created.status()).isEqualTo(200);
        String etag = created.header("ETag");

        Map<String, ObjectNode> changes = new LinkedHashMap<>();
        ObjectNode base = gitlabBody(null);
        base.put("baseUrl", gitlab.url() + "/other");
        changes.put("baseUrl", base);
        ObjectNode authorize = gitlabBody(null);
        ((ObjectNode) authorize.path("oauth")).put("authorizeUrl", "https://gitlab.test/oauth/authorize2");
        changes.put("authorizeUrl", authorize);
        ObjectNode token = gitlabBody(null);
        ((ObjectNode) token.path("oauth")).put("tokenUrl", gitlab.url() + "/oauth/token2");
        changes.put("tokenUrl", token);
        ObjectNode client = gitlabBody(null);
        ((ObjectNode) client.path("oauth")).put("clientId", "client-two");
        changes.put("clientId", client);
        ObjectNode revoke = gitlabBody(null);
        revoke.put("revokeUrl", gitlab.url() + "/oauth/revoke-elsewhere");
        changes.put("revokeUrl", revoke);
        changes.forEach((what, body) -> {
            BrokerClient.Response refused = replace(id, body, etag);
            assertThat(refused.status()).as(what).isEqualTo(422);
            assertThat(Contracts.brokerSchemaErrors("SystemRejected", refused.json())).isEmpty();
            assertThat(refused.json().path("reason").stringValue()).as(what).isEqualTo("client_secret_required");
        });
        assertThat(secretVersionOf(id)).as("nothing was written").isEqualTo(1);
        assertThat(get(id).header("ETag")).isEqualTo(etag);

        ObjectNode scopes = gitlabBody(null);
        ((ObjectNode) scopes.path("oauth")).putArray("scopes").add("api");
        scopes.put("timeout", "PT20S");
        BrokerClient.Response unchanged = replace(id, scopes, etag);
        assertThat(unchanged.status()).as("scopes and timeout are not addresses").isEqualTo(200);
        assertThat(secretVersionOf(id)).isEqualTo(1);

        BrokerClient.Response moved = replace(id, withSecret(base, "test-only-rotated-client-secret-0002"), unchanged.header("ETag"));
        assertThat(moved.status()).isEqualTo(200);
        assertThat(storedSecret(id, secretVersionOf(id)).path("client_secret").stringValue()).isEqualTo("test-only-rotated-client-secret-0002");
        assertThat(moved.body()).doesNotContain("test-only-rotated");
    }

    private static ObjectNode withSecret(ObjectNode body, String secret) {
        ObjectNode copy = body.deepCopy();
        ((ObjectNode) copy.path("oauth")).put("clientSecret", secret);
        return copy;
    }

    // Validation ------------------------------------------------------------------------------------------

    @Test
    void theConfigurationIsCheckedPerAdapterAndCredentialType() {
        String id = newId();
        Map<String, ObjectNode> bodies = new LinkedHashMap<>();
        ObjectNode defaultType = jiraBody(env.upstreamUrl());
        defaultType.put("defaultType", "user-oauth");
        bodies.put("default_type_not_supported", defaultType);
        ObjectNode mixed = jiraBody(env.upstreamUrl());
        mixed.put("adapter", "generic-rest").remove("product");
        ((tools.jackson.databind.node.ArrayNode) mixed.path("supportedTypes")).add("service-account");
        mixed.put("defaultType", "service-account");
        bodies.put("credential_types_mixed", mixed);
        ObjectNode mismatch = jiraBody(env.upstreamUrl());
        mismatch.put("adapter", "generic-rest").remove("product");
        bodies.put("adapter_type_mismatch", mismatch);
        ObjectNode noOauth = gitlabBody(null);
        noOauth.remove("oauth");
        bodies.put("oauth_required", noOauth);
        ObjectNode scheme = jiraBody(env.upstreamUrl());
        scheme.put("secretScheme", "Token");
        bodies.put("secret_scheme_not_supported", scheme);
        ObjectNode noProduct = jiraBody(env.upstreamUrl());
        noProduct.remove("product");
        bodies.put("product_required", noProduct);
        ObjectNode productOnGitlab = gitlabBody(SECRET);
        productOnGitlab.put("product", "jira");
        ObjectNode authorizeOnly = gitlabBody(SECRET);
        ((ObjectNode) authorizeOnly.path("oauth")).remove("tokenUrl");
        bodies.put("oauth_required", authorizeOnly);
        bodies.forEach((reason, body) -> {
            BrokerClient.Response response = create(id, body);
            assertThat(response.status()).as(reason).isEqualTo(422);
            assertThat(Contracts.brokerSchemaErrors("SystemRejected", response.json())).isEmpty();
            assertThat(response.json().path("reason").stringValue()).isEqualTo(reason);
        });
        assertThat(create(id, productOnGitlab).json().path("reason").stringValue()).isEqualTo("product_required");
        ObjectNode unknown = jiraBody(env.upstreamUrl());
        unknown.put("adapter", "unknown");
        assertThat(create(id, unknown).status()).isEqualTo(400);
        ObjectNode ftp = jiraBody("ftp://x.test");
        assertThat(create(id, ftp).status()).isEqualTo(400);
        ObjectNode extra = jiraBody(env.upstreamUrl());
        extra.put("extra", 1);
        assertThat(create(id, extra).status()).isEqualTo(400);
        ObjectNode otherProduct = jiraBody(env.upstreamUrl());
        otherProduct.put("product", "bitbucket");
        assertThat(create(id, otherProduct).status()).isEqualTo(400);
        assertThat(get(id).status()).isEqualTo(404);
    }

    @Test
    void tokenExchangeTakesTheAudienceAndAlwaysTheTokenEndpointOfTheIdentityProvider() {
        String id = newId();
        ObjectNode exchange = Contracts.JSON.createObjectNode();
        exchange.put("baseUrl", env.upstreamUrl()).put("adapter", "opensearch");
        exchange.putArray("supportedTypes").add("token-exchange");
        exchange.put("defaultType", "token-exchange").put("secretScheme", "Bearer").put("exchangeAudience", "aud-" + id);
        ObjectNode oauth = exchange.putObject("oauth");
        oauth.put("clientId", "idp-client").put("clientSecret", SECRET);
        oauth.putArray("scopes").add("aud-scope");

        BrokerClient.Response withUrl = create(id, withTokenUrl(exchange, "https://elsewhere.test/token"));
        assertThat(withUrl.status()).isEqualTo(422);
        assertThat(withUrl.json().path("reason").stringValue()).isEqualTo("token_url_not_settable");
        assertThat(get(id).status()).isEqualTo(404);

        ObjectNode withoutAudience = exchange.deepCopy();
        withoutAudience.remove("exchangeAudience");
        assertThat(create(id, withoutAudience).json().path("reason").stringValue()).isEqualTo("exchange_audience_required");
        ObjectNode withAuthorize = exchange.deepCopy();
        ((ObjectNode) withAuthorize.path("oauth")).put("authorizeUrl", "https://elsewhere.test/authorize");
        assertThat(create(id, withAuthorize).json().path("reason").stringValue()).isEqualTo("authorize_url_not_settable");

        BrokerClient.Response created = create(id, exchange);
        assertThat(created.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("SystemAdminView", created.json())).isEmpty();
        assertThat(created.json().path("exchangeAudience").stringValue()).isEqualTo("aud-" + id);
        assertThat(created.json().path("oauth").path("tokenUrl").stringValue()).isEqualTo(env.idp.tokenUrl());
        assertThat(created.json().path("oauth").has("authorizeUrl")).isFalse();
        assertThat(registry.find(id)).hasValueSatisfying(system -> assertThat(system.tokenExchanger()).isPresent());
    }

    private ObjectNode exchangeBody(String audience) {
        ObjectNode exchange = Contracts.JSON.createObjectNode();
        exchange.put("baseUrl", env.upstreamUrl()).put("adapter", "opensearch");
        exchange.putArray("supportedTypes").add("token-exchange");
        exchange.put("defaultType", "token-exchange").put("secretScheme", "Bearer").put("exchangeAudience", audience);
        ObjectNode oauth = exchange.putObject("oauth");
        oauth.put("clientId", "idp-client").put("clientSecret", SECRET);
        return exchange;
    }

    @Test
    void aTokenExchangeSystemMayOnlyNameAnAllowedAudience(CapturedOutput output) {
        for (String audience : List.of("opensearch", "aud-reports", "aud-")) {
            assertThat(create(newId(), exchangeBody(audience)).status()).as(audience).isEqualTo(200);
        }
        for (String audience : List.of("billing-api", "aud", "opensearch2", "OPENSEARCH", "https://evil.test")) {
            String id = newId();
            String rid = TestTokens.newRequestId();
            BrokerClient.Response refused = bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), rid,
                    exchangeBody(audience).toString(), Map.of("If-None-Match", "*"));
            assertThat(refused.status()).as(audience).isEqualTo(422);
            assertThat(Contracts.brokerSchemaErrors("SystemRejected", refused.json())).isEmpty();
            assertThat(refused.json().path("reason").stringValue()).isEqualTo("audience_not_allowed");
            assertThat(AuditLines.of(output, rid)).as(audience).singleElement().satisfies(event -> {
                assertThat(event.path("outcome").stringValue()).isEqualTo("denied");
                assertThat(event.path("reason").stringValue()).isEqualTo("audience_not_allowed");
            });
            assertThat(get(id).status()).isEqualTo(404);
            assertThat(storedSecretExists(id)).as("no secret was written for a refused system").isFalse();
        }
    }

    private boolean storedSecretExists(String id) {
        return env.bao("GET", "secret/data/mcp/system-clients/" + id, null).statusCode() == 200;
    }

    @Test
    void aReplaceCannotMoveAnAllowedSystemToAnAudienceThatIsNot() {
        String id = newId();
        BrokerClient.Response created = create(id, exchangeBody("aud-notes"));
        assertThat(created.status()).isEqualTo(200);

        BrokerClient.Response refused = replace(id, exchangeBody("billing-api"), created.header("ETag"));

        assertThat(refused.status()).isEqualTo(422);
        assertThat(refused.json().path("reason").stringValue()).isEqualTo("audience_not_allowed");
        assertThat(get(id).json().path("exchangeAudience").stringValue()).isEqualTo("aud-notes");
        assertThat(replace(id, exchangeBody("aud-other"), created.header("ETag")).status()).isEqualTo(200);
    }

    @Test
    void aStoredSystemWhoseAudienceIsNoLongerAllowedIsRefusedAtResolveAndNothingIsSent() {
        String id = newId();
        env.putSystem(new pl.aiwcorpo.mcp.broker.system.SystemDefinition(id, URI.create(env.upstreamUrl()), "opensearch", null,
                List.of(pl.aiwcorpo.mcp.broker.credential.CredentialType.TOKEN_EXCHANGE),
                pl.aiwcorpo.mcp.broker.credential.CredentialType.TOKEN_EXCHANGE, pl.aiwcorpo.mcp.broker.credential.CredentialScheme.BEARER,
                new pl.aiwcorpo.mcp.broker.system.SystemDefinition.Oauth("idp-client", null, URI.create(env.idp.tokenUrl()), null,
                        List.of()),
                1, null, "billing-api", null, null, pl.aiwcorpo.mcp.broker.system.SystemDefinition.newToken(),
                pl.aiwcorpo.mcp.broker.system.SystemDefinition.newToken()));
        registry.reload();
        String sub = UUID.randomUUID().toString();
        String subjectToken = tokens.subjectToken(sub, "alice");
        env.idp.issues(subjectToken, "must-never-be-issued", 300);
        int before = env.idp.requests().size();
        String rid = TestTokens.newRequestId();

        BrokerClient.Response resolved = gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", rid), rid,
                "{\"system\":\"" + id + "\",\"subjectToken\":\"" + subjectToken + "\"}");

        assertThat(resolved.status()).isEqualTo(503);
        assertThat(resolved.body()).doesNotContain("must-never-be-issued");
        assertThat(env.idp.requests()).as("the identity provider was not asked").hasSize(before);
        assertThat(resolve(sub, "opensearch").status()).as("an allowed system is not affected").isNotEqualTo(503);
    }

    @Test
    void withoutAConfiguredListNoTokenExchangeSystemCanBeCreated() throws Exception {
        try (BrokerProcess strict = BrokerProcess.start(env, PORT_STRICT_INSTANCE, Map.of("broker.token-exchange.allowed-audiences", ""))) {
            BrokerClient other = new BrokerClient(env.pki.clientContext(env.bffClient), strict.port());
            String id = newId();
            BrokerClient.Response refused = other.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), null,
                    exchangeBody("opensearch").toString(), Map.of("If-None-Match", "*"));
            assertThat(refused.status()).isEqualTo(422);
            assertThat(refused.json().path("reason").stringValue()).isEqualTo("audience_not_allowed");
            ObjectNode jira = jiraBody(env.upstreamUrl());
            assertThat(other.send("PUT", "/v1/admin/systems/" + newId(), tokens.bffAdmin(adminSub, "root"), null, jira.toString(),
                    Map.of("If-None-Match", "*")).status()).as("other types are not affected").isEqualTo(200);
        }
    }

    private static ObjectNode withTokenUrl(ObjectNode body, String url) {
        ObjectNode copy = body.deepCopy();
        ((ObjectNode) copy.path("oauth")).put("tokenUrl", url);
        return copy;
    }

    @Test
    void anAtlassianSystemNamesItsProductAndTheBrokerCallsThatProductsPath() {
        String id = newId();
        ObjectNode confluence = jiraBody(env.confluenceUrl());
        confluence.put("product", "confluence");
        assertThat(create(id, confluence).status()).isEqualTo(200);
        int before = env.confluenceWhoamiCalls.get();
        String sub = UUID.randomUUID().toString();
        assertThat(bff.send("PUT", "/v1/connections/" + id + "/secret", tokens.bffUser(sub, "alice"), null,
                "{\"secret\":\"alice-pat\"}").status()).isEqualTo(200);
        assertThat(env.confluenceWhoamiCalls.get()).as("Confluence's path, and no probing of Jira's").isEqualTo(before + 1);
    }

    // Authorization ---------------------------------------------------------------------------------------

    @Test
    void onlyAnAdministratorThroughTheBffMayChangeSystems(CapturedOutput output) {
        String id = newId();
        String rid = TestTokens.newRequestId();
        BrokerClient.Response notAdmin = bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffUser(adminSub, "alice"), rid,
                gitlabBody(SECRET).toString(), Map.of("If-None-Match", "*"));
        assertThat(notAdmin.status()).isEqualTo(403);
        assertThat(notAdmin.body()).isEqualTo("{\"error\":\"forbidden\"}");
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> {
            assertThat(event.path("event").stringValue()).isEqualTo("admin_change");
            assertThat(event.path("outcome").stringValue()).isEqualTo("denied");
            assertThat(event.path("reason").stringValue()).isEqualTo("not_admin");
        });
        assertThat(bff.send("GET", "/v1/admin/systems", tokens.bffUser(adminSub, "alice"), null, null).status()).isEqualTo(403);
        assertThat(bff.send("DELETE", "/v1/admin/systems/jira", tokens.bffUser(adminSub, "alice"), null, null).status()).isEqualTo(403);
        assertThat(bff.send("GET", "/v1/admin/systems", null, null, null).status()).isEqualTo(401);

        String gatewayRid = TestTokens.newRequestId();
        assertThat(gateway.send("GET", "/v1/admin/systems", tokens.gatewayUser(adminSub, "root", gatewayRid), gatewayRid, null).status())
                .as("the gateway certificate is not allowed on the admin operations").isEqualTo(403);
        BrokerClient offboarding = new BrokerClient(env.pki.clientContext(env.offboardingClient), port);
        assertThat(offboarding.send("GET", "/v1/admin/systems", null, null, null).status()).isEqualTo(403);
        assertThat(env.systems.find(id)).isEmpty();
        assertThat(registry.find("jira")).isPresent();
    }

    @Test
    void anAdminWriteNeedsAnMfaOfTheLastFiveMinutes(CapturedOutput output) {
        String id = newId();
        BrokerClient.Response created = create(id, gitlabBody(SECRET));
        assertThat(created.status()).isEqualTo(200);
        String etag = created.header("ETag");

        String stale = tokens.bffAdmin(adminSub, "root", Instant.now().minusSeconds(301));
        String rid = TestTokens.newRequestId();
        BrokerClient.Response refused = bff.send("PUT", "/v1/admin/systems/" + id, stale, rid, gitlabBody(null).toString(),
                Map.of("If-Match", etag));
        assertThat(refused.status()).isEqualTo(401);
        assertThat(refused.body()).isEqualTo("{\"error\":\"step_up_required\"}");
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> {
            assertThat(event.path("outcome").stringValue()).isEqualTo("denied");
            assertThat(event.path("reason").stringValue()).isEqualTo("step_up_required");
            assertThat(event.path("errorCode").stringValue()).isEqualTo("step_up_required");
        });
        assertThat(bff.send("DELETE", "/v1/admin/systems/" + id, stale, null, null, Map.of("If-Match", etag)).status()).isEqualTo(401);
        String withoutAuthTime = tokens.idpToken(TestTokens.IDP_ISSUER, adminSub, "root", "mcp-portal-bff", "mcp-credential-broker",
                Instant.now().plusSeconds(300), com.nimbusds.jose.JOSEObjectType.JWT, List.of("mcp-platform-admin"));
        assertThat(put(id, gitlabBody(null), Map.of("If-Match", etag), withoutAuthTime).status()).as("no auth_time at all").isEqualTo(401);
        assertThat(get(id).header("ETag")).as("nothing changed").isEqualTo(etag);

        String fresh = tokens.bffAdmin(adminSub, "root", Instant.now().minusSeconds(290));
        assertThat(put(id, gitlabBody(null), Map.of("If-Match", etag), fresh).status()).isEqualTo(200);
        assertThat(bff.send("GET", "/v1/admin/systems", stale, null, null).status()).as("a read needs no fresh MFA").isEqualTo(200);
    }

    @Test
    void aRecentLoginIsNotAnMfa(CapturedOutput output) {
        String id = newId();
        BrokerClient.Response created = create(id, gitlabBody(SECRET));
        String etag = created.header("ETag");
        Instant recent = Instant.now().minusSeconds(20);

        Map<String, Map<String, Object>> notProofs = new LinkedHashMap<>();
        notProofs.put("no acr and no amr", Map.of());
        notProofs.put("a password only", Map.of("amr", List.of("pwd")));
        notProofs.put("an acr nobody configured", Map.of("acr", "urn:other:level"));
        notProofs.put("an amr that is not a list of methods", Map.of("amr", "otp"));
        for (var notProof : notProofs.entrySet()) {
            String rid = TestTokens.newRequestId();
            BrokerClient.Response refused = bff.send("PUT", "/v1/admin/systems/" + id,
                    tokens.bffAdmin(adminSub, "root", recent, notProof.getValue()), rid, gitlabBody(null).toString(),
                    Map.of("If-Match", etag));
            assertThat(refused.status()).as(notProof.getKey()).isEqualTo(401);
            assertThat(refused.body()).isEqualTo("{\"error\":\"step_up_required\"}");
            assertThat(AuditLines.of(output, rid)).as(notProof.getKey()).singleElement()
                    .satisfies(event -> assertThat(event.path("reason").stringValue()).isEqualTo("step_up_required"));
            assertThat(bff.send("DELETE", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root", recent, notProof.getValue()),
                    null, null, Map.of("If-Match", etag)).status()).as(notProof.getKey()).isEqualTo(401);
        }
        assertThat(get(id).header("ETag")).as("nothing changed").isEqualTo(etag);

        Map<String, Map<String, Object>> proofs = new LinkedHashMap<>();
        proofs.put("amr otp", Map.of("amr", List.of("pwd", "otp")));
        proofs.put("amr hwk", Map.of("amr", List.of("hwk")));
        proofs.put("amr mfa", Map.of("amr", List.of("mfa")));
        proofs.put("amr totp", Map.of("amr", List.of("totp")));
        proofs.put("a configured acr", Map.of("acr", "urn:test:mfa"));
        String current = etag;
        for (var proof : proofs.entrySet()) {
            BrokerClient.Response changed = put(id, gitlabBody(null), Map.of("If-Match", current),
                    tokens.bffAdmin(adminSub, "root", recent, proof.getValue()));
            assertThat(changed.status()).as(proof.getKey()).isEqualTo(200);
            current = changed.header("ETag");
        }
        assertThat(put(id, gitlabBody(null), Map.of("If-Match", current),
                tokens.bffAdmin(adminSub, "root", Instant.now().minusSeconds(400), Map.of("amr", List.of("otp")))).status())
                .as("a proof that is too old").isEqualTo(401);
    }

    @Test
    void theUserSecretSchemeOfTheContractIsBearerOrBasic() {
        for (String scheme : List.of("Token", "ApiKey", "Nonsense")) {
            ObjectNode body = jiraBody(env.upstreamUrl());
            body.put("userSecretScheme", scheme);
            assertThat(create(newId(), body).status()).as(scheme).isEqualTo(400);
        }
        ObjectNode basic = jiraBody(env.upstreamUrl());
        basic.put("userSecretScheme", "Basic");
        assertThat(create(newId(), basic).status()).isEqualTo(200);
    }

    // Invalidation of connections (CC-238 C1) -------------------------------------------------------------

    @Test
    void aChangeOfBaseUrlInvalidatesTheConnectionsAndSendsNothingToTheOldOrTheNewBackend(CapturedOutput output) throws Exception {
        Recorder oldBackend = new Recorder();
        Recorder newBackend = new Recorder();
        String id = newId();
        BrokerClient.Response created = create(id, jiraBody(oldBackend.url()));
        assertThat(created.status()).isEqualTo(200);
        String alice = UUID.randomUUID().toString();
        String bob = UUID.randomUUID().toString();
        String version = connectUserSecret(id, alice, "alice-pat");
        connectUserSecret(id, bob, "bob-pat");
        String path = "secret/data/mcp/connections/" + new SecretKey(alice, id, version).relativePath();
        assertThat(env.bao("GET", path, null).statusCode()).isEqualTo(200);
        assertThat(connectionStatus(alice, id)).isEqualTo("connected");
        int oldBefore = oldBackend.requests.get();

        try (InvalidationListener invalidations = new InvalidationListener(env)) {
            String rid = TestTokens.newRequestId();
            BrokerClient.Response moved = bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), rid,
                    jiraBody(newBackend.url()).toString(), Map.of("If-Match", created.header("ETag")));
            assertThat(moved.status()).isEqualTo(200);

            Set<String> subs = new java.util.HashSet<>();
            for (int i = 0; i < 2; i++) {
                JsonNode event = invalidations.next(5000);
                assertThat(event).as("credential.invalidated " + i).isNotNull();
                assertThat(event.path("system").stringValue()).isEqualTo(id);
                subs.add(event.path("sub").stringValue());
            }
            assertThat(subs).containsExactlyInAnyOrder(alice, bob);
            assertThat(AuditLines.of(output, rid)).extracting(event -> event.path("event").stringValue() + ":" + event.path("reason").stringValue())
                    .contains("admin_change:system_updated", "admin_change:connections_invalidated");
        }

        assertThat(oldBackend.requests.get()).as("nothing was sent to the old address").isEqualTo(oldBefore);
        assertThat(newBackend.requests.get()).as("nor to the new one").isZero();
        assertThat(env.bao("GET", path, null).statusCode()).as("the stored secret was deleted").isEqualTo(404);
        assertThat(rows(id)).as("the rows stay, so the user sees what to do").isEqualTo(2);
        assertThat(connectionStatus(alice, id)).isEqualTo("needs_reconnect");
        BrokerClient.Response refused = resolve(alice, id);
        assertThat(refused.status()).isEqualTo(409);
        assertThat(refused.json().path("error").stringValue()).isEqualTo("credential_required");
        assertThat(oldBackend.requests.get() + newBackend.requests.get()).isEqualTo(oldBefore);

        connectUserSecret(id, alice, "alice-pat");
        assertThat(newBackend.requests.get()).as("connecting again asks the new backend").isEqualTo(1);
        assertThat(connectionStatus(alice, id)).isEqualTo("connected");
        assertThat(resolve(alice, id).status()).isEqualTo(200);
        assertThat(connectionStatus(bob, id)).isEqualTo("needs_reconnect");
    }

    @Test
    void aChangeOfAnyOauthAddressOrTheClientInvalidatesGrantsWithoutRevokingThem() {
        String id = newId();
        ObjectNode current = gitlabBody(null);
        current.put("revokeUrl", gitlab.url() + "/oauth/revoke");
        String etag = create(id, withSecret(current, SECRET)).header("ETag");
        String sub = UUID.randomUUID().toString();
        GitLabStub.Grant grant = connectOauth(id, sub, 7200);
        assertThat(connectionStatus(sub, id)).isEqualTo("connected");

        Map<String, java.util.function.Consumer<ObjectNode>> changes = new LinkedHashMap<>();
        changes.put("authorizeUrl", change -> ((ObjectNode) change.path("oauth")).put("authorizeUrl", "https://gitlab.test/oauth/other"));
        changes.put("tokenUrl", change -> ((ObjectNode) change.path("oauth")).put("tokenUrl", gitlab.url() + "/oauth/token?other=1"));
        changes.put("clientId", change -> ((ObjectNode) change.path("oauth")).put("clientId", "client-two"));
        changes.put("revokeUrl", change -> change.put("revokeUrl", gitlab.url() + "/oauth/revoke?other=1"));
        int round = 0;
        for (var change : changes.entrySet()) {
            int requestsBefore = gitlab.requestCount();
            ObjectNode next = current.deepCopy();
            change.getValue().accept(next);
            BrokerClient.Response moved = replace(id, withSecret(next, SECRET + "-" + round++), etag);
            assertThat(moved.status()).as(change.getKey()).isEqualTo(200);
            etag = moved.header("ETag");
            current = next;
            assertThat(gitlab.requestCount()).as(change.getKey() + ": no call to the provider").isEqualTo(requestsBefore);
            assertThat(connectionStatus(sub, id)).as(change.getKey()).isEqualTo("needs_reconnect");
            assertThat(resolve(sub, id).status()).isEqualTo(409);
            connectOauth(id, sub, 7200);
            assertThat(connectionStatus(sub, id)).isEqualTo("connected");
        }
        assertThat(gitlab.revokeRequests()).as("the first grant was never revoked").noneMatch(form -> grant.accessToken().equals(form.get("token")));
    }

    @Test
    void aChangeThatDoesNotMoveTheSystemLeavesTheConnectionsAlone() throws Exception {
        Recorder backend = new Recorder();
        String id = newId();
        BrokerClient.Response created = create(id, jiraBody(backend.url()));
        String sub = UUID.randomUUID().toString();
        connectUserSecret(id, sub, "alice-pat");

        ObjectNode timeout = jiraBody(backend.url());
        timeout.put("timeout", "PT20S");
        BrokerClient.Response changed = replace(id, timeout, created.header("ETag"));
        assertThat(changed.status()).isEqualTo(200);

        assertThat(connectionStatus(sub, id)).isEqualTo("connected");
        assertThat(resolve(sub, id).status()).isEqualTo(200);
    }

    @Test
    void aConnectionWithoutAClientRevisionIsNeverUsedAndIsInvalidatedWithTheRest() {
        String id = newId();
        ObjectNode body = gitlabBody(null);
        body.put("revokeUrl", gitlab.url() + "/oauth/revoke");
        BrokerClient.Response created = create(id, withSecret(body, SECRET));
        String sub = UUID.randomUUID().toString();
        GitLabStub.Grant grant = connectOauth(id, sub, 90);
        String version = jdbc.sql("select secret_version from connection where sub = :sub and system = :system")
                .param("sub", sub).param("system", id).query(String.class).single();
        jdbc.sql("update connection set client_revision = null where sub = :sub and system = :system")
                .param("sub", sub).param("system", id).update();
        int requests = gitlab.requestCount();

        assertThat(resolve(sub, id).status()).as("a connection nobody vouches for is not refreshed, though its token is due").isEqualTo(409);
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", grant.refreshToken())).isEmpty();
        assertThat(gitlab.requestCount()).isEqualTo(requests);

        ObjectNode moved = body.deepCopy();
        ((ObjectNode) moved.path("oauth")).put("tokenUrl", gitlab.url() + "/oauth/token?moved=1");
        assertThat(replace(id, withSecret(moved, SECRET + "-2"), created.header("ETag")).status()).isEqualTo(200);

        assertThat(connectionStatus(sub, id)).isEqualTo("needs_reconnect");
        assertThat(env.bao("GET", "secret/data/mcp/connections/" + new SecretKey(sub, id, version).relativePath(), null).statusCode())
                .as("its stored value is gone").isEqualTo(404);
        assertThat(gitlab.requestCount()).as("and nothing was sent anywhere").isEqualTo(requests);
    }

    @Test
    void theInvalidationOfAChangeIsFinishedByTheNextWriteWhenItWasInterrupted() throws Exception {
        Recorder oldBackend = new Recorder();
        Recorder newBackend = new Recorder();
        String id = newId();
        BrokerClient.Response created = create(id, jiraBody(oldBackend.url()));
        String sub = UUID.randomUUID().toString();
        String version = connectUserSecret(id, sub, "alice-pat");
        String path = "secret/data/mcp/connections/" + new SecretKey(sub, id, version).relativePath();
        String revisionBefore = jdbc.sql("select client_revision from target_system where id = :id").param("id", id).query(String.class).single();

        BrokerClient.Response moved = replace(id, jiraBody(newBackend.url()), created.header("ETag"));
        assertThat(moved.status()).isEqualTo(200);
        assertThat(jdbc.sql("select client_revision from target_system where id = :id").param("id", id).query(String.class).single())
                .isNotEqualTo(revisionBefore);

        // As if the process had died after the transaction: the connection is marked, its stored value is still there.
        jdbc.sql("update connection set secret_version = :version where sub = :sub and system = :system")
                .param("version", version).param("sub", sub).param("system", id).update();
        assertThat(env.bao("POST", path, "{\"data\":{\"ciphertext\":\"vault:v1:left-behind\"}}").statusCode()).isEqualTo(200);
        ObjectNode timeout = jiraBody(newBackend.url());
        timeout.put("timeout", "PT20S");
        assertThat(replace(id, timeout, moved.header("ETag")).status()).isEqualTo(200);

        assertThat(env.bao("GET", path, null).statusCode()).as("the next write deleted it").isEqualTo(404);
        assertThat(jdbc.sql("select count(*) from connection where sub = :sub and system = :system and secret_version is not null")
                .param("sub", sub).param("system", id).query(Long.class).single()).isZero();
        assertThat(connectionStatus(sub, id)).isEqualTo("needs_reconnect");
    }

    @Test
    void aPendingOauthFlowDiesWhenTheSystemMovesOrIsMadeAgain() {
        String id = newId();
        BrokerClient.Response created = create(id, gitlabBody(SECRET));
        String sub = UUID.randomUUID().toString();
        BrokerClient.Response started = bff.send("POST", "/v1/connections/" + id + "/oauth/start", tokens.bffUser(sub, "alice"), null,
                "{\"returnPath\":\"/catalog\"}");
        assertThat(started.status()).isEqualTo(200);

        ObjectNode moved = gitlabBody(SECRET);
        ((ObjectNode) moved.path("oauth")).put("clientId", "client-two");
        assertThat(replace(id, moved, created.header("ETag")).status()).isEqualTo(200);
        int tokenRequests = gitlab.tokenRequests().size();

        BrokerClient.Response late = complete(id, sub, started, gitlab.issueCode("alice", 7200).code());
        assertThat(late.status()).isEqualTo(422);
        assertThat(late.json().path("error").stringValue()).isEqualTo("flow_invalid");
        assertThat(gitlab.tokenRequests()).as("the code was not exchanged").hasSize(tokenRequests);

        BrokerClient.Response again = bff.send("POST", "/v1/connections/" + id + "/oauth/start", tokens.bffUser(sub, "alice"), null,
                "{\"returnPath\":\"/catalog\"}");
        assertThat(deleteCurrent(id).status()).isEqualTo(204);
        assertThat(create(id, gitlabBody(SECRET)).status()).isEqualTo(200);
        BrokerClient.Response afterRecreate = complete(id, sub, again, gitlab.issueCode("alice", 7200).code());
        assertThat(afterRecreate.status()).as("a flow of the deleted system does not complete on the new one").isEqualTo(422);
    }

    @Test
    void aGrantOfAnotherRevisionIsNeverRefreshedOrRevoked() {
        String id = newId();
        ObjectNode body = gitlabBody(SECRET);
        body.put("revokeUrl", gitlab.url() + "/oauth/revoke");
        create(id, body);
        String sub = UUID.randomUUID().toString();
        GitLabStub.Grant grant = connectOauth(id, sub, 90);
        jdbc.sql("update connection set client_revision = 'issued-under-another-definition' where sub = :sub and system = :system")
                .param("sub", sub).param("system", id).update();
        int requests = gitlab.requestCount();

        BrokerClient.Response resolved = resolve(sub, id);
        assertThat(resolved.status()).as("the access token is due, and it may not be refreshed with this definition").isEqualTo(409);
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", grant.refreshToken())).isEmpty();

        BrokerClient.Response disconnected = bff.send("DELETE", "/v1/connections/" + id, tokens.bffUser(sub, "alice"), null, null);
        assertThat(disconnected.status()).isEqualTo(204);
        assertThat(gitlab.requestCount()).as("not revoked at the provider either").isEqualTo(requests);
        assertThat(rows(id)).isZero();
    }

    // Leftovers and stale instances (I3) ------------------------------------------------------------------

    @Test
    void deletingASystemRemovesTheConnectionsOfUsersAndPublishesInvalidation(CapturedOutput output) throws Exception {
        Recorder backend = new Recorder();
        String id = newId();
        assertThat(create(id, jiraBody(backend.url())).status()).isEqualTo(200);
        String alice = UUID.randomUUID().toString();
        String bob = UUID.randomUUID().toString();
        String aliceVersion = connectUserSecret(id, alice, "alice-pat");
        connectUserSecret(id, bob, "bob-pat");
        String alicePath = "secret/data/mcp/connections/" + new SecretKey(alice, id, aliceVersion).relativePath();
        assertThat(env.bao("GET", alicePath, null).statusCode()).isEqualTo(200);
        assertThat(resolve(alice, id).status()).isEqualTo(200);
        int requests = backend.requests.get();
        String rid = TestTokens.newRequestId();

        try (InvalidationListener invalidations = new InvalidationListener(env)) {
            BrokerClient.Response deleted = bff.send("DELETE", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), rid, null,
                    Map.of("If-Match", get(id).header("ETag")));
            assertThat(deleted.status()).isEqualTo(204);

            Set<String> subs = new java.util.HashSet<>();
            for (int i = 0; i < 2; i++) {
                JsonNode event = invalidations.next(5000);
                assertThat(event).as("credential.invalidated " + i).isNotNull();
                assertThat(event.path("system").stringValue()).isEqualTo(id);
                subs.add(event.path("sub").stringValue());
            }
            assertThat(subs).containsExactlyInAnyOrder(alice, bob);
        }
        assertThat(rows(id)).isZero();
        assertThat(backend.requests.get()).as("nothing is sent to the backend on a delete").isEqualTo(requests);
        assertThat(env.bao("GET", alicePath, null).statusCode()).as("the stored value").isEqualTo(404);
        assertThat(env.bao("GET", alicePath.replace("/data/", "/metadata/"), null).statusCode()).as("every version").isEqualTo(404);

        String afterRid = TestTokens.newRequestId();
        BrokerClient.Response refused = gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(alice, "alice", afterRid),
                afterRid, "{\"system\":\"" + id + "\"}");
        assertThat(refused.status()).isEqualTo(422);
        assertThat(refused.body()).isEqualTo("{\"error\":\"system_not_configured\"}");
        assertThat(AuditLines.of(output, rid)).extracting(event -> event.path("event").stringValue() + ":" + event.path("reason").stringValue())
                .contains("admin_change:system_deleted", "admin_change:connections_invalidated", "connection_change:system_deleted");
        assertThat(AuditLines.of(output, afterRid)).singleElement()
                .satisfies(event -> assertThat(event.has("server")).as("an id that no system has is not written").isFalse());
    }

    @Test
    void aDeleteOfAnIdWithoutASystemIsNoContentAndDeletesNoSecret(CapturedOutput output) {
        String known = newId();
        create(known, gitlabBody(SECRET));
        String mistyped = newId();
        assertThat(env.bao("POST", "secret/data/mcp/system-clients/" + mistyped, "{\"data\":{\"client_secret\":\"not-yours\"}}").statusCode())
                .isEqualTo(200);
        String rid = TestTokens.newRequestId();

        BrokerClient.Response response = bff.send("DELETE", "/v1/admin/systems/" + mistyped, tokens.bffAdmin(adminSub, "root"), rid, null);

        assertThat(response.status()).isEqualTo(204);
        assertThat(storedSecret(mistyped, 1).path("client_secret").stringValue()).isEqualTo("not-yours");
        assertThat(storedSecret(known, 1)).isNotNull();
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> {
            assertThat(event.path("reason").stringValue()).isEqualTo("nothing_to_delete");
            assertThat(event.has("server")).isFalse();
        });
        assertThat(bff.send("DELETE", "/v1/admin/systems/Not-A-System", tokens.bffAdmin(adminSub, "root"), null, null).status())
                .as("a malformed id is not an id nobody has").isEqualTo(400);
        env.bao("DELETE", "secret/metadata/mcp/system-clients/" + mistyped, null);
    }

    @Test
    void aWriteOfAnInstanceThatDoesNotKnowTheDeleteYetFailsAndLeavesNothingBehind() throws Exception {
        Recorder backend = new Recorder();
        String id = newId();
        assertThat(create(id, jiraBody(backend.url())).status()).isEqualTo(200);
        try (BrokerProcess stale = BrokerProcess.start(env, PORT_STALE_INSTANCE, Map.of("broker.system-sync.interval", "1h"))) {
            BrokerClient other = new BrokerClient(env.pki.clientContext(env.bffClient), stale.port());
            assertThat(deleteCurrent(id).status()).isEqualTo(204);
            String sub = UUID.randomUUID().toString();

            BrokerClient.Response write = other.send("PUT", "/v1/connections/" + id + "/secret", tokens.bffUser(sub, "alice"), null,
                    "{\"secret\":\"alice-pat\"}");

            assertThat(write.status()).as("the stale instance still has the system, the database refuses the row").isEqualTo(503);
            assertThat(rows(id)).isZero();
            String hash = SecretKey.hashOf(sub);
            assertThat(env.bao("LIST", "secret/metadata/mcp/connections/" + hash + "/", null).statusCode())
                    .as("and the value it wrote is gone").isEqualTo(404);
        }
    }

    @Test
    void aSystemMadeAgainDoesNotReviveWhatTheOldOneLeftBehind(CapturedOutput output) throws Exception {
        Recorder backend = new Recorder();
        String id = newId();
        assertThat(create(id, jiraBody(backend.url())).status()).isEqualTo(200);
        String sub = UUID.randomUUID().toString();
        String version = connectUserSecret(id, sub, "alice-pat");
        String path = "secret/data/mcp/connections/" + new SecretKey(sub, id, version).relativePath();

        // A delete that an old instance could not finish: the row of the system is gone, a connection stayed (1.x rows are
        // not covered by the foreign key either).
        try (Connection raw = DriverManager.getConnection(env.postgres.getJdbcUrl(), env.postgres.getUsername(), env.postgres.getPassword())) {
            raw.createStatement().execute("set session_replication_role = replica");
            raw.createStatement().execute("delete from target_system where id = '" + id + "'");
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        registry.reload();
        assertThat(rows(id)).isEqualTo(1);
        assertThat(env.bao("GET", path, null).statusCode()).isEqualTo(200);

        String rid = TestTokens.newRequestId();
        BrokerClient.Response created = bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), rid,
                jiraBody(backend.url()).toString(), Map.of("If-None-Match", "*"));
        assertThat(created.status()).isEqualTo(200);

        assertThat(rows(id)).as("purged before the system was made").isZero();
        assertThat(env.bao("GET", path, null).statusCode()).isEqualTo(404);
        assertThat(connectionStatus(sub, id)).isNull();
        assertThat(resolve(sub, id).status()).isEqualTo(409);
        assertThat(AuditLines.of(output, rid)).extracting(event -> event.path("event").stringValue() + ":" + event.path("reason").stringValue())
                .contains("admin_change:system_created", "admin_change:connections_invalidated");
    }

    // Propagation and the rest ----------------------------------------------------------------------------

    @Test
    void everyChangeLeavesAnAdminChangeEvent(CapturedOutput output) {
        String id = newId();
        String createRid = TestTokens.newRequestId();
        BrokerClient.Response created = bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), createRid,
                gitlabBody(SECRET).toString(), Map.of("If-None-Match", "*"));
        String updateRid = TestTokens.newRequestId();
        ObjectNode scopes = gitlabBody(null);
        ((ObjectNode) scopes.path("oauth")).putArray("scopes").add("api");
        BrokerClient.Response updated = bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), updateRid,
                scopes.toString(), Map.of("If-Match", created.header("ETag")));
        String refusedRid = TestTokens.newRequestId();
        bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), refusedRid, gitlabBody(SECRET).toString(),
                Map.of("If-Match", created.header("ETag")));
        String deleteRid = TestTokens.newRequestId();
        bff.send("DELETE", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), deleteRid, null,
                Map.of("If-Match", updated.header("ETag")));
        assertThat(updated.status()).isEqualTo(200);

        assertThat(AuditLines.of(output, createRid)).singleElement().satisfies(event -> {
            assertThat(event.path("event").stringValue()).isEqualTo("admin_change");
            assertThat(event.path("reason").stringValue()).isEqualTo("system_created");
            assertThat(event.path("outcome").stringValue()).isEqualTo("ok");
            assertThat(event.path("server").stringValue()).isEqualTo("mcp-" + id);
            assertThat(event.path("sub").stringValue()).isEqualTo(adminSub);
            assertThat(event.path("username").stringValue()).isEqualTo("root");
        });
        assertThat(AuditLines.of(output, updateRid)).singleElement()
                .satisfies(event -> assertThat(event.path("reason").stringValue()).isEqualTo("system_updated"));
        assertThat(AuditLines.of(output, refusedRid)).singleElement().satisfies(event -> {
            assertThat(event.path("outcome").stringValue()).isEqualTo("denied");
            assertThat(event.path("reason").stringValue()).isEqualTo("precondition_failed");
        });
        assertThat(AuditLines.of(output, deleteRid)).singleElement()
                .satisfies(event -> assertThat(event.path("reason").stringValue()).isEqualTo("system_deleted"));
    }

    @Test
    void theServerOfAnAuditEventIsAnIdThatHasASystemOrIsBeingMadeOrRemoved(CapturedOutput output) {
        String unknown = newId();
        String getRid = TestTokens.newRequestId();
        bff.send("GET", "/v1/admin/systems/" + unknown, tokens.bffAdmin(adminSub, "root"), getRid, null);
        String reservedRid = TestTokens.newRequestId();
        bff.send("PUT", "/v1/admin/systems/gateway", tokens.bffAdmin(adminSub, "root"), reservedRid, gitlabBody(SECRET).toString(),
                Map.of("If-None-Match", "*"));
        String sub = UUID.randomUUID().toString();
        String resolveRid = TestTokens.newRequestId();
        gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", resolveRid), resolveRid,
                "{\"system\":\"" + unknown + "\"}");

        for (String rid : List.of(reservedRid, resolveRid)) {
            assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> assertThat(event.has("server")).isFalse());
        }
        assertThat(AuditLines.of(output, getRid)).isEmpty();
    }

    @Test
    void aChangeIsVisibleToAnotherInstanceWithoutRestart() throws Exception {
        try (BrokerProcess second = BrokerProcess.start(env, PORT_SECOND_INSTANCE, Map.of())) {
            BrokerClient other = new BrokerClient(env.pki.clientContext(env.gatewayClient), second.port());
            String id = newId();
            assertThat(systemsOf(other)).doesNotContainKey(id);

            BrokerClient.Response created = create(id, gitlabBody(SECRET));
            assertThat(created.status()).isEqualTo(200);
            awaitSystems(other, systems -> systems.containsKey(id));
            assertThat(systemsOf(other).get(id).path("oauthScopes").get(0).stringValue()).isEqualTo("read_api");

            ObjectNode scopes = gitlabBody(null);
            ((ObjectNode) scopes.path("oauth")).putArray("scopes").add("api");
            assertThat(replace(id, scopes, created.header("ETag")).status()).isEqualTo(200);
            awaitSystems(other, systems -> systems.containsKey(id) && "api".equals(systems.get(id).path("oauthScopes").get(0).stringValue()));

            assertThat(deleteCurrent(id).status()).isEqualTo(204);
            awaitSystems(other, systems -> !systems.containsKey(id));
            assertThat(second.alive()).isTrue();
        }
    }

    private Map<String, JsonNode> systemsOf(BrokerClient client) {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response response = client.send("GET", "/v1/systems", tokens.gatewayService(rid), rid, null);
        assertThat(response.status()).isEqualTo(200);
        Map<String, JsonNode> byId = new LinkedHashMap<>();
        response.json().forEach(system -> byId.put(system.path("system").stringValue(), system));
        return byId;
    }

    private void awaitSystems(BrokerClient client, Predicate<Map<String, JsonNode>> condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (System.nanoTime() < deadline) {
            if (condition.test(systemsOf(client))) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("the other instance did not pick up the change in 15 s: " + systemsOf(client).keySet());
    }

    @Test
    void aConnectionWhoseTypeTheSystemNoLongerTakesMustBeMadeAgain() throws Exception {
        Recorder backend = new Recorder();
        String id = newId();
        BrokerClient.Response created = create(id, jiraBody(backend.url()));
        String sub = UUID.randomUUID().toString();
        connectUserSecret(id, sub, "alice-pat");

        ObjectNode serviceKey = Contracts.JSON.createObjectNode();
        serviceKey.put("baseUrl", backend.url()).put("adapter", "generic-rest");
        serviceKey.putArray("supportedTypes").add("service-account");
        serviceKey.put("defaultType", "service-account").put("secretScheme", "Bearer");
        assertThat(replace(id, serviceKey, created.header("ETag")).status()).isEqualTo(200);

        assertThat(connectionStatus(sub, id)).isEqualTo("needs_reconnect");
    }
}
