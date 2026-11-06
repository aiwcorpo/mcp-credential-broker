package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/** A generic-rest system with user secrets (CC-247): a whoami the administrator configures, or no verification at all. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class GenericRestUserSecretIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final Set<String> STANDARD = Set.of("jira", "confluence", "gitlab", "opensearch");

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
    final String adminSub = UUID.randomUUID().toString();
    HttpServer backend;
    final List<String> requests = Collections.synchronizedList(new ArrayList<>());
    final List<String> elsewhere = Collections.synchronizedList(new ArrayList<>());
    HttpServer other;

    @BeforeEach
    void start() throws IOException {
        bff = new BrokerClient(env.pki.clientContext(env.bffClient), port);
        gateway = new BrokerClient(env.pki.clientContext(env.gatewayClient), port);
        other = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        other.createContext("/", exchange -> {
            elsewhere.add(exchange.getRequestURI().toString());
            reply(exchange, 200, "{\"username\":\"redirected\"}");
        });
        other.start();
        backend = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        backend.createContext("/", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            requests.add(exchange.getRequestURI().toString() + " " + auth);
            String path = exchange.getRequestURI().getPath();
            String secret = auth == null ? "" : auth.substring(auth.indexOf(' ') + 1);
            if (auth != null && auth.startsWith("Basic ")) {
                String pair = new String(Base64.getDecoder().decode(secret), StandardCharsets.UTF_8);
                secret = pair.substring(pair.indexOf(':') + 1);
            }
            if (secret.startsWith("bad")) {
                reply(exchange, 401, "{}");
            } else if (secret.startsWith("forbidden")) {
                reply(exchange, 403, "{}");
            } else if (secret.startsWith("boom")) {
                reply(exchange, 500, "{}");
            } else if (secret.startsWith("redirect")) {
                exchange.getResponseHeaders().add("Location", "http://127.0.0.1:" + other.getAddress().getPort() + "/stolen");
                reply(exchange, 302, "");
            } else if (path.equals("/api/me")) {
                reply(exchange, 200, "{\"username\":\"alice\",\"id\":7}");
            } else if (path.equals("/api/nested")) {
                reply(exchange, 200, "{\"data\":{\"user\":{\"login\":\"bob\"}}}");
            } else if (path.equals("/api/empty")) {
                reply(exchange, 200, "{\"username\":\"\"}");
            } else if (path.equals("/api/number")) {
                reply(exchange, 200, "{\"username\":42}");
            } else if (path.equals("/api/created")) {
                reply(exchange, 201, "{\"username\":\"carol\"}");
            } else {
                reply(exchange, 200, "{\"other\":1}");
            }
        });
        backend.start();
    }

    @AfterEach
    void stop() {
        backend.stop(0);
        other.stop(0);
        requests.clear();
        elsewhere.clear();
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

    private static void reply(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, status == 302 ? -1 : bytes.length);
        if (status != 302) {
            exchange.getResponseBody().write(bytes);
        }
        exchange.close();
    }

    private static String newId() {
        return "n" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
    }

    private String url() {
        return "http://127.0.0.1:" + backend.getAddress().getPort();
    }

    private ObjectNode body(String path, String field) {
        ObjectNode body = Contracts.JSON.createObjectNode();
        body.put("baseUrl", url()).put("adapter", "generic-rest");
        body.putArray("supportedTypes").add("user-secret");
        body.put("defaultType", "user-secret").put("secretScheme", "Bearer");
        if (path != null) {
            body.putObject("whoami").put("path", path).put("usernameField", field);
        }
        return body;
    }

    private BrokerClient.Response put(String id, ObjectNode body, Map<String, String> headers) {
        return bff.send("PUT", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), TestTokens.newRequestId(), body.toString(), headers);
    }

    private BrokerClient.Response create(String id, ObjectNode body) {
        return put(id, body, Map.of("If-None-Match", "*"));
    }

    private BrokerClient.Response connect(String id, String sub, String secret) {
        return bff.send("PUT", "/v1/connections/" + id + "/secret", tokens.bffUser(sub, "alice"), null, "{\"secret\":\"" + secret + "\"}");
    }

    private JsonNode info(String id) {
        String rid = TestTokens.newRequestId();
        for (JsonNode system : gateway.send("GET", "/v1/systems", tokens.gatewayService(rid), rid, null).json()) {
            if (id.equals(system.path("system").stringValue())) {
                assertThat(Contracts.brokerSchemaErrors("SystemInfo", system)).isEmpty();
                return system;
            }
        }
        throw new AssertionError("no system " + id);
    }

    private JsonNode connectionOf(String sub, String id) {
        for (JsonNode connection : bff.send("GET", "/v1/connections", tokens.bffUser(sub, "alice"), null, null).json()) {
            if (id.equals(connection.path("system").stringValue())) {
                assertThat(Contracts.brokerSchemaErrors("Connection", connection)).isEmpty();
                return connection;
            }
        }
        return null;
    }

    @Test
    void aSecretIsCheckedWithTheWhoamiAndStoredWithTheNameItReturns() {
        String id = newId();
        BrokerClient.Response created = create(id, body("/api/me", "username"));
        assertThat(created.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("SystemAdminView", created.json())).isEmpty();
        assertThat(created.json().path("whoami").path("path").stringValue()).isEqualTo("/api/me");
        assertThat(created.json().path("whoami").path("usernameField").stringValue()).isEqualTo("username");
        assertThat(info(id).path("userSecretVerified").booleanValue()).isTrue();

        String sub = UUID.randomUUID().toString();
        BrokerClient.Response stored = connect(id, sub, "good-token-1");

        assertThat(stored.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("PutSecretResponse", stored.json())).isEmpty();
        assertThat(stored.json().path("backendUser").stringValue()).isEqualTo("alice");
        assertThat(stored.json().path("verified").booleanValue()).isTrue();
        assertThat(requests).containsExactly("/api/me Bearer good-token-1");
        assertThat(connectionOf(sub, id).path("backendUser").stringValue()).isEqualTo("alice");
        assertThat(connectionOf(sub, id).path("verified").booleanValue()).isTrue();

        String rid = TestTokens.newRequestId();
        BrokerClient.Response resolved = gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", rid), rid,
                "{\"system\":\"" + id + "\"}");
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("ResolvedCredential", resolved.json())).isEmpty();
        assertThat(resolved.json().path("scheme").stringValue()).isEqualTo("Bearer");
        assertThat(resolved.json().path("value").stringValue()).isEqualTo("good-token-1");
        assertThat(resolved.json().path("type").stringValue()).isEqualTo("user-secret");
    }

    @Test
    void anyTwoHundredWithTheFieldStoresTheSecret() {
        String id = newId();
        assertThat(create(id, body("/api/created", "username")).status()).isEqualTo(200);
        BrokerClient.Response stored = connect(id, UUID.randomUUID().toString(), "good-token-2");
        assertThat(stored.status()).isEqualTo(200);
        assertThat(stored.json().path("backendUser").stringValue()).isEqualTo("carol");
    }

    @Test
    void aJsonPointerNamesTheField() {
        String id = newId();
        assertThat(create(id, body("/api/nested", "/data/user/login")).status()).isEqualTo(200);
        BrokerClient.Response stored = connect(id, UUID.randomUUID().toString(), "good-token-3");
        assertThat(stored.status()).isEqualTo(200);
        assertThat(stored.json().path("backendUser").stringValue()).isEqualTo("bob");
    }

    @Test
    void aRejectedSecretIsInvalidAndNothingIsStored() {
        String id = newId();
        create(id, body("/api/me", "username"));
        for (String secret : List.of("bad-token", "forbidden-token")) {
            String sub = UUID.randomUUID().toString();
            BrokerClient.Response refused = connect(id, sub, secret);
            assertThat(refused.status()).as(secret).isEqualTo(422);
            assertThat(refused.body()).isEqualTo("{\"error\":\"secret_invalid\"}");
            assertThat(connectionOf(sub, id)).isNull();
        }
    }

    @Test
    void anAnswerThatIsNotAUsableNameOrAServerErrorIsUpstreamUnavailable() {
        String id = newId();
        create(id, body("/api/me", "username"));
        String missing = newId();
        create(missing, body("/api/me", "no_such_field"));
        String nested = newId();
        create(nested, body("/api/nested", "/data/user/nothing"));
        String empty = newId();
        create(empty, body("/api/empty", "username"));
        String number = newId();
        create(number, body("/api/number", "username"));

        for (String[] attempt : new String[][] {{id, "boom-token"}, {missing, "good-token"}, {nested, "good-token"},
                {empty, "good-token"}, {number, "good-token"}}) {
            String sub = UUID.randomUUID().toString();
            BrokerClient.Response refused = connect(attempt[0], sub, attempt[1]);
            assertThat(refused.status()).as(attempt[0]).isEqualTo(503);
            assertThat(refused.body()).isEqualTo("{\"error\":\"upstream_unavailable\"}");
            assertThat(connectionOf(sub, attempt[0])).isNull();
        }
    }

    @Test
    void aRedirectIsNotFollowedAndTheSecretGoesNowhereElse() {
        String id = newId();
        create(id, body("/api/me", "username"));

        BrokerClient.Response refused = connect(id, UUID.randomUUID().toString(), "redirect-token");

        assertThat(refused.status()).isEqualTo(503);
        assertThat(elsewhere).as("the host the redirect named got nothing").isEmpty();
    }

    @Test
    void aBasicSystemSendsTheLoginAndTheTokenAsBasic() {
        String id = newId();
        ObjectNode basic = body("/api/me", "username");
        basic.put("secretScheme", "Basic");
        assertThat(create(id, basic).status()).isEqualTo(200);

        BrokerClient.Response stored = bff.send("PUT", "/v1/connections/" + id + "/secret", tokens.bffUser(UUID.randomUUID().toString(), "alice"),
                null, "{\"username\":\"alice.smith\",\"secret\":\"api-token-9\"}");

        assertThat(stored.status()).isEqualTo(200);
        assertThat(requests).singleElement().satisfies(request -> {
            assertThat(request).startsWith("/api/me Basic ");
            assertThat(new String(Base64.getDecoder().decode(request.substring("/api/me Basic ".length())), StandardCharsets.UTF_8))
                    .isEqualTo("alice.smith:api-token-9");
        });
    }

    @Test
    void withoutAWhoamiTheSecretIsStoredUnverifiedWithNoBackendUser(CapturedOutput output) {
        String id = newId();
        assertThat(create(id, body(null, null)).status()).isEqualTo(200);
        assertThat(info(id).path("userSecretVerified").booleanValue()).isFalse();
        String sub = UUID.randomUUID().toString();
        String rid = TestTokens.newRequestId();

        BrokerClient.Response stored = bff.send("PUT", "/v1/connections/" + id + "/secret", tokens.bffUser(sub, "alice"), rid,
                "{\"secret\":\"whatever-token\"}");

        assertThat(stored.status()).isEqualTo(200);
        assertThat(Contracts.brokerSchemaErrors("PutSecretResponse", stored.json())).isEmpty();
        assertThat(stored.json().path("backendUser").isNull()).isTrue();
        assertThat(stored.json().path("verified").booleanValue()).isFalse();
        assertThat(requests).as("nothing was asked of the system").isEmpty();
        JsonNode connection = connectionOf(sub, id);
        assertThat(connection.path("backendUser").isNull()).isTrue();
        assertThat(connection.path("verified").booleanValue()).isFalse();
        assertThat(connection.path("status").stringValue()).isEqualTo("connected");
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(event -> {
            assertThat(event.path("reason").stringValue()).isEqualTo("secret_stored_unverified");
            assertThat(event.path("outcome").stringValue()).isEqualTo("ok");
            assertThat(event.has("backendUser")).isFalse();
        });

        String resolveRid = TestTokens.newRequestId();
        BrokerClient.Response resolved = gateway.send("POST", "/v1/credentials/resolve", tokens.gatewayUser(sub, "alice", resolveRid),
                resolveRid, "{\"system\":\"" + id + "\"}");
        assertThat(resolved.status()).isEqualTo(200);
        assertThat(resolved.json().path("value").stringValue()).isEqualTo("whatever-token");
        assertThat(bff.send("DELETE", "/v1/connections/" + id, tokens.bffUser(sub, "alice"), null, null).status()).isEqualTo(204);
    }

    @Test
    void theOtherSystemsKeepTheirVerification() {
        assertThat(info("jira").path("userSecretVerified").booleanValue()).isTrue();
        assertThat(info("gitlab").path("userSecretVerified").booleanValue()).isTrue();
        assertThat(info("opensearch").has("userSecretVerified")).isFalse();
    }

    @Test
    void aChangeOfWhoamiKeepsTheConnectionsAndAChangeOfBaseUrlInvalidatesThem() throws Exception {
        String id = newId();
        BrokerClient.Response created = create(id, body("/api/me", "username"));
        String sub = UUID.randomUUID().toString();
        assertThat(connect(id, sub, "good-token-4").status()).isEqualTo(200);

        BrokerClient.Response changed = put(id, body("/api/nested", "/data/user/login"), Map.of("If-Match", created.header("ETag")));
        assertThat(changed.status()).isEqualTo(200);
        assertThat(connectionOf(sub, id).path("status").stringValue()).as("same host, same connections").isEqualTo("connected");

        BrokerClient.Response dropped = put(id, body(null, null), Map.of("If-Match", changed.header("ETag")));
        assertThat(dropped.status()).isEqualTo(200);
        assertThat(dropped.json().has("whoami")).isFalse();
        assertThat(connectionOf(sub, id).path("status").stringValue()).isEqualTo("connected");

        ObjectNode moved = body(null, null);
        moved.put("baseUrl", "http://127.0.0.1:" + other.getAddress().getPort());
        assertThat(put(id, moved, Map.of("If-Match", dropped.header("ETag"))).status()).isEqualTo(200);
        assertThat(connectionOf(sub, id).path("status").stringValue()).isEqualTo("needs_reconnect");
        assertThat(requests).as("nothing was sent after the first check").hasSize(1);
        assertThat(elsewhere).isEmpty();
    }

    @Test
    void theWhoamiOfTheRequestIsChecked() {
        String id = newId();
        for (String path : List.of("api/me", "//evil.test/x", "/a/../b", "/a?x=1", "/a#frag", "http://evil.test/x", "/" + "a".repeat(512),
                "/with space", "/ok/..", "")) {
            assertThat(create(id, body(path, "username")).status()).as("path '" + path + "'").isEqualTo(400);
        }
        for (String field : List.of("1abc", "a b", "/", "/a//b", "a.b", "/a/b/c/d/e/f/g/h/i", "", "x".repeat(65))) {
            assertThat(create(id, body("/api/me", field)).status()).as("field '" + field + "'").isEqualTo(400);
        }
        ObjectNode withoutField = body("/api/me", "username");
        ((ObjectNode) withoutField.path("whoami")).remove("usernameField");
        assertThat(create(id, withoutField).status()).isEqualTo(400);
        ObjectNode extra = body("/api/me", "username");
        ((ObjectNode) extra.path("whoami")).put("method", "POST");
        assertThat(create(id, extra).status()).isEqualTo(400);
        assertThat(env.systems.find(id)).isEmpty();

        for (String path : List.of("/", "/api/me", "/v1/users/current", "/a/b.c~d_e-f%20g")) {
            assertThat(create(newId(), body(path, "username")).status()).as("path '" + path + "'").isEqualTo(200);
        }
        for (String field : List.of("username", "_id", "user-name", "/data/user/login", "/a")) {
            assertThat(create(newId(), body("/api/me", field)).status()).as("field '" + field + "'").isEqualTo(200);
        }
    }

    @Test
    void theCredentialTypesOfGenericRestAreUserSecretOrServiceAccount() {
        String id = newId();
        ObjectNode oauth = body(null, null);
        ((tools.jackson.databind.node.ArrayNode) oauth.path("supportedTypes")).removeAll().add("user-oauth");
        oauth.put("defaultType", "user-oauth");
        ObjectNode client = oauth.putObject("oauth");
        client.put("clientId", "c").put("clientSecret", "test-only-secret").put("authorizeUrl", "https://x.test/a").put("tokenUrl", "https://x.test/t");
        BrokerClient.Response refused = create(id, oauth);
        assertThat(refused.status()).isEqualTo(422);
        assertThat(refused.json().path("reason").stringValue()).isEqualTo("credential_type_not_supported_by_adapter");

        ObjectNode mixed = body(null, null);
        ((tools.jackson.databind.node.ArrayNode) mixed.path("supportedTypes")).add("service-account");
        assertThat(create(id, mixed).json().path("reason").stringValue()).isEqualTo("credential_types_mixed");

        ObjectNode serviceWithWhoami = body("/api/me", "username");
        ((tools.jackson.databind.node.ArrayNode) serviceWithWhoami.path("supportedTypes")).removeAll().add("service-account");
        serviceWithWhoami.put("defaultType", "service-account");
        assertThat(create(id, serviceWithWhoami).json().path("reason").stringValue()).isEqualTo("whoami_not_applicable");

        ObjectNode jiraWithWhoami = Contracts.JSON.createObjectNode();
        jiraWithWhoami.put("baseUrl", env.upstreamUrl()).put("adapter", "atlassian-dc").put("product", "jira");
        jiraWithWhoami.putArray("supportedTypes").add("user-secret");
        jiraWithWhoami.put("defaultType", "user-secret").put("secretScheme", "Bearer");
        jiraWithWhoami.putObject("whoami").put("path", "/api/me").put("usernameField", "username");
        assertThat(create(id, jiraWithWhoami).status()).as("whoami exists only for generic-rest").isEqualTo(400);
        assertThat(env.systems.find(id)).isEmpty();

        ObjectNode service = body(null, null);
        ((tools.jackson.databind.node.ArrayNode) service.path("supportedTypes")).removeAll().add("service-account");
        service.put("defaultType", "service-account");
        assertThat(create(newId(), service).status()).isEqualTo(200);
    }

    @Test
    void theAdminViewIsTheSameAsTheListAndHasNoWhoamiWhenThereIsNone() {
        String id = newId();
        create(id, body(null, null));
        BrokerClient.Response read = bff.send("GET", "/v1/admin/systems/" + id, tokens.bffAdmin(adminSub, "root"), null, null);
        assertThat(read.json().has("whoami")).isFalse();
        assertThat(Contracts.brokerSchemaErrors("SystemAdminView", read.json())).isEmpty();
        Map<String, JsonNode> byId = new LinkedHashMap<>();
        bff.send("GET", "/v1/admin/systems", tokens.bffAdmin(adminSub, "root"), null, null).json()
                .forEach(system -> byId.put(system.path("system").stringValue(), system));
        assertThat(byId.get(id)).isEqualTo(read.json());
    }
}
