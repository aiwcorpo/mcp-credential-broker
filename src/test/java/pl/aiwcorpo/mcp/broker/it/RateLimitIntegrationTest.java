package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.BrokerClient;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.support.TestTokens;

/**
 * The per-user limits of the OAuth operations (CC-156): over the limit the answer is 429 rate_limited with Retry-After
 * and the audit says so; another user is not affected. The limit of authenticator enrollment starts (CC-151) is
 * tested with the authenticator.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class RateLimitIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        env.registerProperties(registry);
    }

    @LocalServerPort
    int port;

    @Autowired
    StringRedisTemplate redis;

    BrokerClient bff;
    TestTokens tokens = env.tokens;

    @BeforeEach
    void clients() {
        bff = new BrokerClient(env.pki.clientContext(env.bffClient), port);
    }

    @Test
    void startsAreLimitedPerUser(CapturedOutput output) {
        String sub = UUID.randomUUID().toString();
        for (int i = 0; i < 10; i++) {
            assertThat(start(sub, null).status()).as("start %d", i + 1).isEqualTo(200);
        }
        String rid = TestTokens.newRequestId();
        BrokerClient.Response limited = start(sub, rid);
        assertThat(limited.status()).isEqualTo(429);
        assertThat(limited.body()).isEqualTo("{\"error\":\"rate_limited\"}");
        assertThat(Contracts.brokerSchemaErrors("Error", limited.json())).isEmpty();
        assertThat(Integer.parseInt(limited.header("Retry-After"))).isBetween(1, 60);
        assertThat(limited.raw().headers().map().keySet()).as("no header names a limit")
                .noneMatch(name -> name.toLowerCase().startsWith("x-ratelimit"));
        assertThat(AuditLines.of(output, rid)).singleElement().satisfies(e -> {
            assertThat(e.path("event").stringValue()).isEqualTo("connection_change");
            assertThat(e.path("reason").stringValue()).isEqualTo("rate_limited");
            assertThat(e.path("outcome").stringValue()).isEqualTo("denied");
            assertThat(e.path("errorCode").stringValue()).isEqualTo("rate_limited");
        });
        assertThat(start(UUID.randomUUID().toString(), null).status()).as("another user").isEqualTo(200);
    }

    @Test
    void completionsAreLimitedPerUserWhateverTheirOutcome() {
        String sub = UUID.randomUUID().toString();
        for (int i = 0; i < 20; i++) {
            BrokerClient.Response refused = complete(sub);
            assertThat(refused.status()).as("completion %d", i + 1).isEqualTo(422);
            assertThat(refused.json().path("error").stringValue()).isEqualTo("flow_invalid");
        }
        BrokerClient.Response limited = complete(sub);
        assertThat(limited.status()).isEqualTo(429);
        assertThat(Integer.parseInt(limited.header("Retry-After"))).isBetween(1, 60);
        assertThat(complete(UUID.randomUUID().toString()).status()).as("another user").isEqualTo(422);
    }

    @Test
    void aCounterThatLostItsExpiryIsGivenOneInsteadOfBlockingTheUserForGood() {
        String sub = UUID.randomUUID().toString();
        String key = "broker:rate:oauth-start:" + SecretKey.hashOf(sub);
        redis.opsForValue().set(key, "500");
        assertThat(redis.getExpire(key)).isEqualTo(-1L);

        BrokerClient.Response limited = start(sub, null);

        assertThat(limited.status()).isEqualTo(429);
        assertThat(redis.getExpire(key)).isBetween(1L, 60L);
    }

    @Test
    void aRedisOutageIsAuditedAsTheLimiterNotTheSecretStore(CapturedOutput output) {
        String rid = TestTokens.newRequestId();
        BrokerClient.Response response;
        env.redis.getDockerClient().pauseContainerCmd(env.redis.getContainerId()).exec();
        try {
            response = start(UUID.randomUUID().toString(), rid);
        } finally {
            env.redis.getDockerClient().unpauseContainerCmd(env.redis.getContainerId()).exec();
        }
        assertThat(response.status()).isEqualTo(503);
        assertThat(AuditLines.of(output, rid)).singleElement()
                .satisfies(e -> assertThat(e.path("reason").stringValue()).isEqualTo("rate_limit_unavailable"));
    }

    private BrokerClient.Response start(String sub, String rid) {
        return bff.send("POST", "/v1/connections/gitlab/oauth/start", tokens.bffUser(sub, "alice"), rid,
                "{\"returnPath\":\"/catalog\"}");
    }

    private BrokerClient.Response complete(String sub) {
        return bff.send("POST", "/v1/connections/gitlab/oauth/complete", tokens.bffUser(sub, "alice"), null,
                "{\"flowId\":\"flow-aaaaaaaaaaaaaaaaaaaaaa\",\"code\":\"c\",\"state\":\"s\"}");
    }
}
