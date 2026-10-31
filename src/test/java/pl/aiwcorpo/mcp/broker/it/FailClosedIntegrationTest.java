package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;

import pl.aiwcorpo.mcp.broker.authenticator.Base32;
import pl.aiwcorpo.mcp.broker.authenticator.Totp;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.GitLabStub;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;

/**
 * Abuse case 15: with Redis, OpenBao or PostgreSQL gone (the container is paused, so connections hang instead of
 * being refused, the harder case) every operation of the broker either does not need that dependency or answers
 * {@code 503 upstream_unavailable} within seconds. Never a success that skipped a check, never a 500, never a hang,
 * and nothing latches: when the dependency is back the same requests work.
 *
 * <p>{@code PUT secret} and {@code DELETE} need Redis for the lock of the connection, so a purge cannot race them.
 * {@code oauth/start} does not need OpenBao or PostgreSQL (its state lives in Redis).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class FailClosedIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();
    private static final TestTokens tokens = env.tokens;
    private static final String TOOL = "delete_issue";
    private static final long SLOWEST_ANSWER_MILLIS = 12_000;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
        // A command that timed out on the paused Redis still runs when it wakes up, so a lock may be taken for nobody;
        // the lease is what frees it, and a short one keeps the test short.
        registry.add("broker.oauth-flow.refresh-lock-lease", () -> "PT8S");
    }

    @LocalServerPort
    int port;

    /** A user with a PAT for Jira, an OAuth grant for GitLab that is due for renewal, and a registered authenticator. */
    record Person(String sub, byte[] seed, GitLabStub.Grant grant, GitLabStub.Grant renewed) {
    }

    @Test
    void redisGone(CapturedOutput output) throws Exception {
        Map<String, Integer> expected = new LinkedHashMap<>();
        expected.put("resolve jira", 503);
        expected.put("resolve gitlab", 503);
        expected.put("verify", 503);
        expected.put("gateway authenticator status", 503);
        expected.put("invalidate-codes", 503);
        expected.put("list connections", 200);
        expected.put("put secret", 503);
        expected.put("oauth start", 503);
        expected.put("enrollment start", 201);
        expected.put("bff authenticator status", 200);
        expected.put("delete connection", 204);
        expected.put("purge", 503);
        runWith(env.redis, expected, output);
    }

    @Test
    void openBaoGone(CapturedOutput output) throws Exception {
        Map<String, Integer> expected = new LinkedHashMap<>();
        expected.put("resolve jira", 503);
        expected.put("resolve gitlab", 503);
        expected.put("verify", 503);
        expected.put("gateway authenticator status", 200);
        expected.put("invalidate-codes", 204);
        expected.put("list connections", 200);
        expected.put("put secret", 503);
        expected.put("oauth start", 200);
        expected.put("enrollment start", 503);
        expected.put("bff authenticator status", 200);
        expected.put("delete connection", 503);
        expected.put("purge", 503);
        runWith(env.openbao, expected, output);
    }

    @Test
    void postgresGone(CapturedOutput output) throws Exception {
        Map<String, Integer> expected = new LinkedHashMap<>();
        expected.put("resolve jira", 503);
        expected.put("resolve gitlab", 503);
        expected.put("verify", 503);
        expected.put("gateway authenticator status", 503);
        expected.put("invalidate-codes", 503);
        expected.put("list connections", 503);
        expected.put("put secret", 503);
        expected.put("oauth start", 200);
        expected.put("enrollment start", 503);
        expected.put("bff authenticator status", 503);
        expected.put("delete connection", 503);
        expected.put("purge", 503);
        runWith(env.postgres, expected, output);
    }

    private void runWith(GenericContainer<?> dependency, Map<String, Integer> expected, CapturedOutput output) throws Exception {
        Clients clients = new Clients(port);
        Person person = person(clients);
        Person fresh = new Person("failclosed-" + UUID.randomUUID(), null, null, null);
        Map<String, Supplier<BrokerClient.Response>> operations = operations(clients, person, fresh);
        assertThat(operations.keySet()).containsExactlyElementsOf(expected.keySet());

        Map<String, BrokerClient.Response> answers = new LinkedHashMap<>();
        Map<String, Long> millis = new HashMap<>();
        pause(dependency);
        try {
            ExecutorService pool = Executors.newFixedThreadPool(operations.size());
            try {
                Map<String, Future<BrokerClient.Response>> running = new LinkedHashMap<>();
                for (var operation : operations.entrySet()) {
                    if (!operation.getKey().equals("delete connection") && !operation.getKey().equals("purge")) {
                        running.put(operation.getKey(), pool.submit(() -> timed(millis, operation.getKey(), operation.getValue())));
                    }
                }
                for (var call : running.entrySet()) {
                    answers.put(call.getKey(), call.getValue().get());
                }
            } finally {
                pool.shutdownNow();
            }
            for (String destructive : List.of("delete connection", "purge")) {
                answers.put(destructive, timed(millis, destructive, operations.get(destructive)));
            }
        } finally {
            unpause(dependency);
        }

        for (var entry : expected.entrySet()) {
            BrokerClient.Response answer = answers.get(entry.getKey());
            assertThat(answer.status()).as(entry.getKey()).isEqualTo(entry.getValue());
            assertThat(millis.get(entry.getKey())).as(entry.getKey() + " answers within seconds").isLessThan(SLOWEST_ANSWER_MILLIS);
            if (answer.status() == 503) {
                assertThat(answer.body()).as(entry.getKey()).isEqualTo("{\"error\":\"upstream_unavailable\"}");
            }
            assertThat(answer.body()).as(entry.getKey() + " carries no credential").doesNotContain("alice-pat")
                    .doesNotContain(person.grant.accessToken()).doesNotContain(person.renewed.accessToken());
        }
        afterwards(clients, person, answers);

        assertThat(output.getAll()).as("an outage is never an unexpected error").doesNotContain("Unhandled ")
                .doesNotContain("\"reason\":\"internal_error\"");
        output.getAll().lines().filter(line -> line.startsWith("{") && line.contains("\"component\":\"broker\""))
                .forEach(line -> assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", Contracts.JSON.readTree(line)))
                        .as(line).isEmpty());
    }

    /** Nothing latched and nothing half-done is left behind: the same user is served again, or is gone when the purge went through. */
    private void afterwards(Clients clients, Person person, Map<String, BrokerClient.Response> answers) {
        int purged = answers.get("purge").status();
        assertThat(purged).isEqualTo(503);
        assertThat(purgeUntilDone(clients, person.sub)).as("the repeated purge finishes the job").isEqualTo(204);
        assertThat(resolve(clients, person.sub, "jira").status()).isEqualTo(409);
        assertThat(resolve(clients, person.sub, "gitlab").status()).isEqualTo(409);
        assertThat(gateway(clients, "GET", "/v1/authenticator", person.sub, null, TOOL).json().path("state").stringValue()).isEqualTo("none");

        Person again = person(clients);
        assertThat(resolve(clients, again.sub, "jira").status()).isEqualTo(200);
        assertThat(resolve(clients, again.sub, "gitlab").json().path("value").stringValue()).isEqualTo(again.renewed.accessToken());
        assertThat(gateway(clients, "POST", "/v1/authenticator/verify", again.sub,
                "{\"code\":\"" + Totp.code(again.seed, Totp.stepOf(Instant.now()) + 1) + "\"}", TOOL).json().path("result").stringValue())
                .isEqualTo("ok");
    }

    /** A lock taken by a command that woke up late frees itself at the end of its lease; the purge is repeated until then. */
    private static int purgeUntilDone(Clients clients, String sub) {
        int status = 0;
        for (int attempt = 0; attempt < 20 && status != 204; attempt++) {
            status = clients.offboarding.send("POST", "/v1/admin/users/" + sub + "/purge", null, null, null).status();
            if (status != 204) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return status;
                }
            }
        }
        return status;
    }

    private Map<String, Supplier<BrokerClient.Response>> operations(Clients c, Person p, Person fresh) {
        Map<String, Supplier<BrokerClient.Response>> operations = new LinkedHashMap<>();
        operations.put("resolve jira", () -> resolve(c, p.sub, "jira"));
        operations.put("resolve gitlab", () -> resolve(c, p.sub, "gitlab"));
        operations.put("verify", () -> gateway(c, "POST", "/v1/authenticator/verify", p.sub,
                "{\"code\":\"" + Totp.code(p.seed, Totp.stepOf(Instant.now()) + 1) + "\"}", TOOL));
        operations.put("gateway authenticator status", () -> gateway(c, "GET", "/v1/authenticator", p.sub, null, TOOL));
        operations.put("invalidate-codes", () -> gateway(c, "POST", "/v1/authenticator/invalidate-codes", p.sub, null, TOOL));
        operations.put("list connections", () -> c.bff.send("GET", "/v1/connections", tokens.bffUser(p.sub, "alice"), null, null));
        operations.put("put secret", () -> c.bff.send("PUT", "/v1/connections/jira/secret", tokens.bffUser(p.sub, "alice"), null,
                "{\"secret\":\"alice-pat\"}"));
        operations.put("oauth start", () -> c.bff.send("POST", "/v1/connections/gitlab/oauth/start", tokens.bffUser(fresh.sub, "alice"),
                null, "{\"returnPath\":\"/catalog\"}"));
        operations.put("enrollment start", () -> c.bff.send("POST", "/v1/authenticator/enrollment", tokens.bffUser(fresh.sub, "alice"), null, null));
        operations.put("bff authenticator status", () -> c.bff.send("GET", "/v1/authenticator", tokens.bffUser(p.sub, "alice"), null, null));
        operations.put("delete connection", () -> c.bff.send("DELETE", "/v1/connections/jira", tokens.bffUser(p.sub, "alice"), null, null));
        operations.put("purge", () -> c.offboarding.send("POST", "/v1/admin/users/" + p.sub + "/purge", null, null, null));
        return operations;
    }

    private static BrokerClient.Response timed(Map<String, Long> millis, String name, Supplier<BrokerClient.Response> call) {
        long start = System.nanoTime();
        try {
            return call.get();
        } finally {
            synchronized (millis) {
                millis.put(name, (System.nanoTime() - start) / 1_000_000);
            }
        }
    }

    private Person person(Clients c) {
        String sub = "failclosed-" + UUID.randomUUID();
        String bffToken = tokens.bffUser(sub, "alice");
        assertThat(c.bff.send("PUT", "/v1/connections/jira/secret", bffToken, null, "{\"secret\":\"alice-pat\"}").status()).isEqualTo(200);

        GitLabStub.Grant grant = env.gitlab.issueCode("alice", 60);
        env.gitlab.revokeAccepts();
        BrokerClient.Response start = c.bff.send("POST", "/v1/connections/gitlab/oauth/start", bffToken, null, "{\"returnPath\":\"/catalog\"}");
        assertThat(start.status()).isEqualTo(200);
        Map<String, String> query = new HashMap<>();
        for (String pair : URI.create(start.json().path("authorizeUrl").stringValue()).getRawQuery().split("&")) {
            int eq = pair.indexOf('=');
            query.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8), URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        assertThat(c.bff.send("POST", "/v1/connections/gitlab/oauth/complete", bffToken, null,
                "{\"flowId\":\"" + start.json().path("flowId").stringValue() + "\",\"code\":\"" + grant.code() + "\",\"state\":\""
                        + query.get("state") + "\"}").status()).isEqualTo(200);
        GitLabStub.Grant renewed = env.gitlab.rotateOnRefresh(grant, 7200, 0);

        BrokerClient.Response enrollment = c.bff.send("POST", "/v1/authenticator/enrollment", bffToken, null, null);
        assertThat(enrollment.status()).isEqualTo(201);
        byte[] seed = Base32.decode(enrollment.json().path("secret").stringValue());
        assertThat(c.bff.send("POST", "/v1/authenticator/enrollment/confirm", bffToken, null,
                "{\"enrollmentId\":\"" + enrollment.json().path("enrollmentId").stringValue() + "\",\"code\":\""
                        + Totp.code(seed, Totp.stepOf(Instant.now())) + "\"}").status()).isEqualTo(200);
        return new Person(sub, seed, grant, renewed);
    }

    private static BrokerClient.Response resolve(Clients c, String sub, String system) {
        return gateway(c, "POST", "/v1/credentials/resolve", sub, "{\"system\":\"" + system + "\"}", "get_issue");
    }

    private static BrokerClient.Response gateway(Clients c, String method, String path, String sub, String body, String tool) {
        String requestId = TestTokens.newRequestId();
        return c.gateway.send(method, path, tokens.gatewayUser(sub, "alice", requestId, tool), requestId, body);
    }

    private static void pause(GenericContainer<?> container) {
        container.getDockerClient().pauseContainerCmd(container.getContainerId()).exec();
    }

    private static void unpause(GenericContainer<?> container) {
        container.getDockerClient().unpauseContainerCmd(container.getContainerId()).exec();
    }

    private record Clients(BrokerClient gateway, BrokerClient bff, BrokerClient offboarding) {
        Clients(int port) {
            this(new BrokerClient(env.pki.clientContext(env.gatewayClient), port),
                    new BrokerClient(env.pki.clientContext(env.bffClient), port),
                    new BrokerClient(env.pki.clientContext(env.offboardingClient), port));
        }
    }
}
