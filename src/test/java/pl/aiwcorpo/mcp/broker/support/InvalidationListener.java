package pl.aiwcorpo.mcp.broker.support;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.pubsub.RedisPubSubAdapter;
import io.lettuce.core.pubsub.StatefulRedisPubSubConnection;
import tools.jackson.databind.JsonNode;

/** Subscribes to credential.invalidated with the Redis admin user and queues what the broker publishes. */
public final class InvalidationListener implements AutoCloseable {

    private final BlockingQueue<String> messages = new LinkedBlockingQueue<>();
    private final RedisClient client;
    private final StatefulRedisPubSubConnection<String, String> connection;

    public InvalidationListener(TestEnvironment env) {
        client = RedisClient.create(RedisURI.builder()
                .withHost(env.redis.getHost()).withPort(env.redis.getMappedPort(6379))
                .withAuthentication("admin", TestEnvironment.REDIS_ADMIN_PASSWORD.toCharArray()).build());
        connection = client.connectPubSub();
        connection.addListener(new RedisPubSubAdapter<>() {
            @Override
            public void message(String channel, String message) {
                messages.add(message);
            }
        });
        connection.sync().subscribe("credential.invalidated");
    }

    /** Next event, or null when none arrives within the wait. */
    public JsonNode next(long millis) {
        try {
            String message = messages.poll(millis, TimeUnit.MILLISECONDS);
            return message == null ? null : Contracts.JSON.readTree(message);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    @Override
    public void close() {
        connection.close();
        client.shutdown();
    }
}
