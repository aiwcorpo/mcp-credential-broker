package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.broker.authenticator.Base32;
import pl.aiwcorpo.mcp.broker.authenticator.Totp;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.BrokerProcess;
import pl.aiwcorpo.mcp.broker.support.GitLabStub;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;

/**
 * Two (and three) broker JVMs on one PostgreSQL, Redis and OpenBao, as replicas behind a load balancer. The
 * authenticator counters, the lock and the burning of codes must hold across instances, an instance killed with
 * SIGKILL must change nothing for the survivor, and nothing the TOTP check relies on may live in the memory of an
 * instance. Ports 18712-18717 are in the range of ws-06 (18710-18719).
 */
class MultiInstanceIntegrationTest {

    private static final int PORT_A = 18712;
    private static final int PORT_B = 18713;
    private static final int PORT_KILLED = 18714;
    private static final String TOOL = "delete_issue";

    private static final TestEnvironment env = TestEnvironment.get();
    private static final TestTokens tokens = env.tokens;
    private static BrokerProcess a;
    private static BrokerProcess b;

    @BeforeAll
    static void twoInstances() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<BrokerProcess> first = pool.submit(() -> BrokerProcess.start(env, PORT_A, Map.of()));
            Future<BrokerProcess> second = pool.submit(() -> BrokerProcess.start(env, PORT_B, Map.of()));
            a = first.get();
            b = second.get();
        } finally {
            pool.shutdown();
        }
    }

    @AfterAll
    static void stop() {
        for (BrokerProcess process : new BrokerProcess[] {a, b}) {
            if (process != null) {
                process.close();
            }
        }
    }

    // Authenticator ---------------------------------------------------------------------------------------

    @Test
    void anEnrollmentStartedOnOneInstanceIsConfirmedAndUsedOnTheOther() {
        String sub = newSub();
        String bffToken = tokens.bffUser(sub, "alice");
        BrokerClient.Response started = bff(a).send("POST", "/v1/authenticator/enrollment", bffToken, null, null);
        assertThat(started.status()).isEqualTo(201);
        byte[] seed = Base32.decode(started.json().path("secret").stringValue());
        String enrollmentId = started.json().path("enrollmentId").stringValue();

        BrokerClient.Response confirmed = bff(b).send("POST", "/v1/authenticator/enrollment/confirm", bffToken, null,
                "{\"enrollmentId\":\"" + enrollmentId + "\",\"code\":\"" + currentCode(seed) + "\"}");
        assertThat(confirmed.status()).isEqualTo(200);
        assertThat(status(a, sub)).isEqualTo("active");
        assertThat(status(b, sub)).isEqualTo("active");

        assertThat(verify(a, sub, nextCode(seed))).isEqualTo("ok");
        assertThat(verify(b, sub, nextCode(seed))).as("the step spent on A is spent on B").isEqualTo("replayed");
    }

    @Test
    void parallelConfirmsOnBothInstancesLeaveOneRegistrationThatCanVerify() throws Exception {
        for (int round = 0; round < 10; round++) {
            String sub = newSub();
            String bffToken = tokens.bffUser(sub, "judy");
            BrokerClient.Response started = bff(a).send("POST", "/v1/authenticator/enrollment", bffToken, null, null);
            byte[] seed = Base32.decode(started.json().path("secret").stringValue());
            String body = "{\"enrollmentId\":\"" + started.json().path("enrollmentId").stringValue() + "\",\"code\":\""
                    + currentCode(seed) + "\"}";
            AtomicInteger turn = new AtomicInteger();
            List<String> statuses = parallel(4, () -> String.valueOf(bff(turn.getAndIncrement() % 2 == 0 ? a : b)
                    .send("POST", "/v1/authenticator/enrollment/confirm", bffToken, null, body).status()));

            assertThat(count(statuses, "200")).as(statuses.toString()).isEqualTo(1);
            assertThat(statuses).containsOnly("200", "422");
            assertThat(verify(b, sub, nextCode(seed))).isEqualTo("ok");
        }
    }

    @Test
    void failuresCountedOnBothInstancesLockAfterExactlyFive() throws Exception {
        Registered user = register("bob");
        String wrong = wrongCode(user.seed);
        AtomicInteger turn = new AtomicInteger();
        List<String> results = parallel(60, () -> verify(turn.getAndIncrement() % 2 == 0 ? a : b, user.sub, wrong));

        assertThat(count(results, "invalid")).isEqualTo(5);
        assertThat(count(results, "locked")).isEqualTo(55);
        assertThat(failures(user.sub)).isEqualTo(5);
        assertThat(verify(a, user.sub, nextCode(user.seed))).isEqualTo("locked");
        assertThat(verify(b, user.sub, nextCode(user.seed))).isEqualTo("locked");
    }

    @Test
    void theSameValidCodeInParallelOnBothInstancesIsAcceptedOnce() throws Exception {
        Registered user = register("carol");
        String code = nextCode(user.seed);
        AtomicInteger turn = new AtomicInteger();
        List<String> results = parallel(30, () -> verify(turn.getAndIncrement() % 2 == 0 ? a : b, user.sub, code));

        assertThat(count(results, "ok")).isEqualTo(1);
        assertThat(results).containsOnly("ok", "replayed", "locked");
    }

    @Test
    void burningCodesOnOneInstanceHoldsOnTheOther() {
        Registered user = register("dave");
        String requestId = TestTokens.newRequestId();
        assertThat(gateway(a).send("POST", "/v1/authenticator/invalidate-codes",
                tokens.gatewayUser(user.sub, "dave", requestId, TOOL), requestId, null).status()).isEqualTo(204);

        assertThat(verify(b, user.sub, nextCode(user.seed))).isEqualTo("burned");
        assertThat(verify(b, user.sub, currentCode(user.seed))).isEqualTo("burned");
        assertThat(failures(user.sub)).as("a burned code is not a wrong guess").isZero();
    }

    @Test
    void anInstanceKilledInTheMiddleOfAttemptsLeavesTheCounterExact() throws Exception {
        Registered user = register("erin");
        String wrong = wrongCode(user.seed);
        try (BrokerProcess doomed = BrokerProcess.start(env, PORT_KILLED, Map.of())) {
            AtomicInteger answered = new AtomicInteger();
            AtomicInteger unreachable = new AtomicInteger();
            AtomicInteger turn = new AtomicInteger();
            List<String> results = parallel(60, () -> {
                BrokerProcess target = turn.getAndIncrement() % 2 == 0 ? doomed : b;
                try {
                    String result = verify(target, user.sub, wrong);
                    if (target == doomed && answered.incrementAndGet() == 2) {
                        doomed.kill();
                    }
                    return result;
                } catch (RuntimeException e) {
                    unreachable.incrementAndGet();
                    return "unreachable";
                }
            });

            assertThat(doomed.alive()).isFalse();
            assertThat(unreachable.get()).as("requests sent to the dead instance fail, none is answered wrongly").isPositive();
            assertThat(count(results, "invalid")).isLessThanOrEqualTo(5);
            assertThat(results).containsOnly("invalid", "locked", "unreachable");
            assertThat(failures(user.sub)).as("committed failures, whoever answered").isEqualTo(5);
            assertThat(verify(b, user.sub, nextCode(user.seed))).isEqualTo("locked");
        }
    }

    @Test
    void aCodeAcceptedByAKilledInstanceStaysSpent() {
        Registered user = register("frank");
        String code = nextCode(user.seed);
        try (BrokerProcess doomed = BrokerProcess.start(env, PORT_KILLED, Map.of())) {
            assertThat(verify(doomed, user.sub, code)).isEqualTo("ok");
            doomed.kill();
        }
        assertThat(verify(b, user.sub, code)).isEqualTo("replayed");
        assertThat(verify(b, user.sub, currentCode(user.seed))).as("an earlier step is spent with the later one").isEqualTo("replayed");
        assertThat(failures(user.sub)).as("a replayed code counts as a wrong guess, like on one instance").isEqualTo(2);
    }

    @Test
    void aRestartedInstanceKnowsTheLockOfItsPredecessor() throws Exception {
        Registered user = register("grace");
        String wrong = wrongCode(user.seed);
        try (BrokerProcess first = BrokerProcess.start(env, PORT_KILLED, Map.of())) {
            for (int i = 0; i < 5; i++) {
                assertThat(verify(first, user.sub, wrong)).isEqualTo("invalid");
            }
            first.kill();
        }
        try (BrokerProcess second = BrokerProcess.start(env, PORT_KILLED, Map.of())) {
            assertThat(verify(second, user.sub, nextCode(user.seed))).isEqualTo("locked");
            assertThat(status(second, user.sub)).isEqualTo("active");
        }
    }

    // Refresh lock ----------------------------------------------------------------------------------------

    @Test
    void parallelResolvesOnBothInstancesRenewOnce() throws Exception {
        GitLabStub gitlab = env.gitlab;
        String sub = newSub();
        GitLabStub.Grant first = gitlab.issueCode("alice", 60);
        connect(a, gitlab, sub, "alice", first);
        GitLabStub.Grant second = gitlab.rotateOnRefresh(first, 7200, 800);

        AtomicInteger turn = new AtomicInteger();
        List<String> values = parallel(10, () -> {
            BrokerClient.Response response = resolve(turn.getAndIncrement() % 2 == 0 ? a : b, sub, "gitlab");
            return response.status() + ":" + response.json().path("value").stringValue();
        });

        assertThat(values).containsOnly("200:" + second.accessToken());
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", first.refreshToken()))
                .as("one refresh token is spent once, whichever instance took the lock").hasSize(1);
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", second.refreshToken())).isEmpty();
    }

    @Test
    void aHolderKilledDuringARefreshBlocksNobodyLongerThanItsLease() throws Exception {
        GitLabStub gitlab = env.gitlab;
        String sub = newSub();
        GitLabStub.Grant first = gitlab.issueCode("alice", 90);
        connect(a, gitlab, sub, "alice", first);
        gitlab.rotateOnRefresh(first, 7200, 6000);

        Map<String, String> shortLease = Map.of("broker.oauth-flow.refresh-lock-lease", "PT10S",
                "broker.systems.gitlab.timeout", "10s");
        String holderOutput;
        try (BrokerProcess holder = BrokerProcess.start(env, PORT_KILLED, shortLease)) {
            ExecutorService pool = Executors.newSingleThreadExecutor();
            try {
                Future<?> blocked = pool.submit(() -> {
                    try {
                        resolve(holder, sub, "gitlab");
                    } catch (RuntimeException expected) {
                        // The connection is cut when the holder is killed.
                    }
                });
                awaitLock(sub);
                // The lock is taken before the provider is asked; the provider takes 6 s, so the holder dies inside the call.
                Thread.sleep(500);
                holder.kill();
                blocked.get();
            } finally {
                pool.shutdownNow();
            }
            holderOutput = holder.output();
        }

        BrokerClient.Response during = resolve(b, sub, "gitlab");
        assertThat(during.status()).as("the access token still works, so the caller is served with it").isEqualTo(200);
        assertThat(during.json().path("value").stringValue()).isEqualTo(first.accessToken());
        assertThat(gitlab.tokenRequests("refresh_token", "refresh_token", first.refreshToken()))
                .as("the survivor does not spend the refresh token while the dead holder's lease runs; holder log: %s; survivor log: %s",
                        tail(holderOutput), tail(b.output()))
                .hasSize(1);

        GitLabStub.Grant second = gitlab.rotateOnRefresh(first, 7200, 0);
        Thread.sleep(7_000);
        BrokerClient.Response after = resolve(b, sub, "gitlab");
        assertThat(after.status()).isEqualTo(200);
        assertThat(after.json().path("value").stringValue()).as("the lease is over, the survivor renews").isEqualTo(second.accessToken());
    }

    // Start-up --------------------------------------------------------------------------------------------

    @Test
    void twoInstancesMigrateAnEmptyDatabaseTogether() throws Exception {
        String url = env.postgres.getJdbcUrl();
        try (Connection admin = DriverManager.getConnection(url, env.postgres.getUsername(), env.postgres.getPassword())) {
            admin.createStatement().execute("create database broker_m5_empty");
        }
        String emptyUrl = url.replace("/broker", "/broker_m5_empty");
        Map<String, String> overrides = Map.of("MCP_DB_URL", emptyUrl);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        List<BrokerProcess> started = new ArrayList<>();
        try {
            Future<BrokerProcess> one = pool.submit(() -> BrokerProcess.start(env, 18715, overrides));
            Future<BrokerProcess> two = pool.submit(() -> BrokerProcess.start(env, 18716, overrides));
            started.add(one.get());
            started.add(two.get());
            try (Connection db = DriverManager.getConnection(emptyUrl, env.postgres.getUsername(), env.postgres.getPassword());
                    ResultSet history = db.createStatement()
                            .executeQuery("select count(*), count(*) filter (where not success) from flyway_schema_history")) {
                history.next();
                assertThat(history.getInt(1)).as("each migration once").isEqualTo(6);
                assertThat(history.getInt(2)).isZero();
            }
            Registered user = register(started.get(0), started.get(1), "heidi");
            assertThat(verify(started.get(1), user.sub, nextCode(user.seed))).isEqualTo("ok");
        } finally {
            started.forEach(BrokerProcess::close);
            pool.shutdownNow();
        }
    }

    // Helpers ---------------------------------------------------------------------------------------------

    record Registered(String sub, byte[] seed) {
    }

    private static Registered register(String username) {
        return register(a, b, username);
    }

    private static Registered register(BrokerProcess starting, BrokerProcess confirming, String username) {
        String sub = newSub();
        String bffToken = tokens.bffUser(sub, username);
        BrokerClient.Response started = bff(starting).send("POST", "/v1/authenticator/enrollment", bffToken, null, null);
        assertThat(started.status()).isEqualTo(201);
        byte[] seed = Base32.decode(started.json().path("secret").stringValue());
        BrokerClient.Response confirmed = bff(confirming).send("POST", "/v1/authenticator/enrollment/confirm", bffToken, null,
                "{\"enrollmentId\":\"" + started.json().path("enrollmentId").stringValue() + "\",\"code\":\""
                        + currentCode(seed) + "\"}");
        assertThat(confirmed.status()).isEqualTo(200);
        return new Registered(sub, seed);
    }

    private static BrokerClient bff(BrokerProcess instance) {
        return new BrokerClient(env.pki.clientContext(env.bffClient), instance.port());
    }

    private static BrokerClient gateway(BrokerProcess instance) {
        return new BrokerClient(env.pki.clientContext(env.gatewayClient), instance.port());
    }

    private static String verify(BrokerProcess instance, String sub, String code) {
        return gatewayCall(instance, "POST", "/v1/authenticator/verify", sub, "{\"code\":\"" + code + "\"}")
                .json().path("result").stringValue();
    }

    private static String status(BrokerProcess instance, String sub) {
        return gatewayCall(instance, "GET", "/v1/authenticator", sub, null).json().path("state").stringValue();
    }

    private static BrokerClient.Response gatewayCall(BrokerProcess instance, String method, String path, String sub, String body) {
        String requestId = TestTokens.newRequestId();
        return gateway(instance).send(method, path, tokens.gatewayUser(sub, "test-user", requestId, TOOL), requestId, body);
    }

    private static BrokerClient.Response resolve(BrokerProcess instance, String sub, String system) {
        String requestId = TestTokens.newRequestId();
        return gateway(instance).send("POST", "/v1/credentials/resolve",
                tokens.gatewayUser(sub, "alice", requestId), requestId, "{\"system\":\"" + system + "\"}");
    }

    private static void connect(BrokerProcess instance, GitLabStub gitlab, String sub, String username, GitLabStub.Grant grant) {
        BrokerClient.Response start = bff(instance).send("POST", "/v1/connections/gitlab/oauth/start",
                tokens.bffUser(sub, username), null, "{\"returnPath\":\"/catalog\"}");
        assertThat(start.status()).isEqualTo(200);
        URI authorize = URI.create(start.json().path("authorizeUrl").stringValue());
        Map<String, String> query = new HashMap<>();
        for (String pair : authorize.getRawQuery().split("&")) {
            int eq = pair.indexOf('=');
            query.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        BrokerClient.Response complete = bff(instance).send("POST", "/v1/connections/gitlab/oauth/complete",
                tokens.bffUser(sub, username), null, "{\"flowId\":\"" + start.json().path("flowId").stringValue()
                        + "\",\"code\":\"" + grant.code() + "\",\"state\":\"" + query.get("state") + "\"}");
        assertThat(complete.status()).isEqualTo(200);
    }

    /** Waits until some instance holds the refresh lock of the user's GitLab connection (read with the admin user of Redis). */
    private static void awaitLock(String sub) throws InterruptedException {
        String key = "broker:oauth:refresh:" + SecretKey.hashOf(sub) + ":gitlab";
        io.lettuce.core.RedisClient client = io.lettuce.core.RedisClient.create(io.lettuce.core.RedisURI.builder()
                .withHost(env.redis.getHost()).withPort(env.redis.getMappedPort(6379))
                .withAuthentication("admin", TestEnvironment.REDIS_ADMIN_PASSWORD.toCharArray()).build());
        try (var connection = client.connect()) {
            long deadline = System.nanoTime() + 20_000_000_000L;
            while (connection.sync().get(key) == null) {
                assertThat(System.nanoTime()).as("the holder took the lock").isLessThan(deadline);
                Thread.sleep(25);
            }
        } finally {
            client.shutdown();
        }
    }

    private static String tail(String output) {
        String[] lines = output.split("\n");
        return String.join(" | ", java.util.Arrays.copyOfRange(lines, Math.max(0, lines.length - 15), lines.length));
    }

    private static int failures(String sub) {
        try (Connection db = DriverManager.getConnection(env.postgres.getJdbcUrl(), env.postgres.getUsername(), env.postgres.getPassword());
                var statement = db.prepareStatement("select count(*) from authenticator_failure where sub = ?")) {
            statement.setString(1, sub);
            try (ResultSet rows = statement.executeQuery()) {
                rows.next();
                return rows.getInt(1);
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String currentCode(byte[] seed) {
        return Totp.code(seed, Totp.stepOf(Instant.now()));
    }

    private static String nextCode(byte[] seed) {
        return Totp.code(seed, Totp.stepOf(Instant.now()) + 1);
    }

    /** A six digit code outside the window, so that a test never hits a valid one by chance. */
    private static String wrongCode(byte[] seed) {
        long step = Totp.stepOf(Instant.now());
        List<String> valid = new ArrayList<>();
        for (long s = step - 2; s <= step + 2; s++) {
            valid.add(Totp.code(seed, s));
        }
        for (int candidate = 100000; ; candidate++) {
            if (!valid.contains(String.valueOf(candidate))) {
                return String.valueOf(candidate);
            }
        }
    }

    private static long count(List<String> results, String value) {
        return results.stream().filter(value::equals).count();
    }

    private static List<String> parallel(int requests, Callable<String> call) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(requests);
        try {
            CountDownLatch go = new CountDownLatch(1);
            List<Future<String>> futures = new ArrayList<>();
            for (int i = 0; i < requests; i++) {
                futures.add(pool.submit(() -> {
                    go.await();
                    return call.call();
                }));
            }
            go.countDown();
            List<String> results = new ArrayList<>();
            for (Future<String> future : futures) {
                results.add(future.get());
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private static String newSub() {
        return "multi-it-" + UUID.randomUUID();
    }
}
