package pl.aiwcorpo.mcp.broker.system;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.sun.net.httpserver.HttpServer;

import tools.jackson.databind.json.JsonMapper;

/** The cap on calls in flight to one target system (L-08) and the timeout rule against the refresh lock lease. */
class UpstreamHttpTest {

    private HttpServer server;
    private ExecutorService callers;
    private final CountDownLatch release = new CountDownLatch(1);
    private final AtomicInteger arrived = new AtomicInteger();
    private final CountDownLatch twoArrived = new CountDownLatch(2);

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        server.createContext("/slow", exchange -> {
            arrived.incrementAndGet();
            twoArrived.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            byte[] body = "{}".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        callers = Executors.newCachedThreadPool();
    }

    @AfterEach
    void stop() {
        release.countDown();
        callers.shutdownNow();
        server.stop(0);
    }

    @Test
    @Timeout(20)
    void aCallBeyondTheLimitOfOneSystemIsRefusedAtOnceAndOtherSystemsKeepTheirs() throws Exception {
        UpstreamLimits limits = new UpstreamLimits(2, Duration.ofSeconds(60));
        HttpClient client = HttpClient.newHttpClient();
        JsonMapper json = JsonMapper.builder().build();
        UpstreamHttp slowSystem = new UpstreamHttp(client, json, limits.inFlight("slow-system"));
        UpstreamHttp sameSystemReplacedAdapter = new UpstreamHttp(client, json, limits.inFlight("slow-system"));
        UpstreamHttp otherSystem = new UpstreamHttp(client, json, limits.inFlight("other-system"));
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/slow"))
                .timeout(Duration.ofSeconds(5)).GET().build();

        List<Future<Integer>> held = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            held.add(callers.submit(() -> slowSystem.send(request).statusCode()));
        }
        assertThat(twoArrived.await(5, TimeUnit.SECONDS)).as("both calls reached the system").isTrue();

        long started = System.nanoTime();
        assertThatThrownBy(() -> sameSystemReplacedAdapter.send(request)).isInstanceOf(UpstreamUnavailableException.class)
                .hasMessageContaining("too many calls in flight");
        assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)).as("refused without waiting").isLessThan(500);
        assertThat(arrived.get()).as("the refused call was not sent").isEqualTo(2);

        Future<Integer> other = callers.submit(() -> otherSystem.send(request).statusCode());
        release.countDown();
        assertThat(other.get()).isEqualTo(200);
        for (Future<Integer> call : held) {
            assertThat(call.get()).isEqualTo(200);
        }
        assertThat(slowSystem.send(request).statusCode()).as("the permits come back when the calls end").isEqualTo(200);
    }

    @Test
    void aTimeoutIsKeptBelowTheRefreshLockLease() {
        UpstreamLimits limits = new UpstreamLimits(20, Duration.ofSeconds(60));
        assertThat(limits.allowsTimeout(Duration.ofSeconds(59))).isTrue();
        assertThat(limits.allowsTimeout(Duration.ofSeconds(60))).isFalse();
        assertThat(limits.effectiveTimeout(Duration.ofSeconds(5))).isEqualTo(Duration.ofSeconds(5));
        assertThat(limits.effectiveTimeout(Duration.ofMinutes(10))).as("a stored longer timeout is served shortened")
                .isEqualTo(Duration.ofSeconds(59));
    }
}
