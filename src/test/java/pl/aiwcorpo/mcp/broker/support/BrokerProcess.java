package pl.aiwcorpo.mcp.broker.support;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import org.springframework.test.context.DynamicPropertyRegistry;

import pl.aiwcorpo.mcp.broker.BrokerApplication;

/**
 * A broker instance as a separate JVM on the test classpath, against the databases of {@link TestEnvironment}: what a
 * second replica behind a load balancer is, including the ways it can die. Ports come from the ws-06 range
 * (18710-18719) so that a test never takes a port of another stream.
 */
public final class BrokerProcess implements AutoCloseable {

    private final int port;
    private final Process process;
    private final Path log;

    private BrokerProcess(int port, Process process, Path log) {
        this.port = port;
        this.process = process;
        this.log = log;
    }

    /**
     * A start that fails only because the database refused the first connection (the container runtime dropping it for a
     * moment) is tried once more; every other failure is the test's result. The test of the migrations uses
     * {@link #startWithoutRetry}, where a failed start is the thing under test.
     */
    public static BrokerProcess start(TestEnvironment env, int port, Map<String, String> overrides) {
        try {
            return startWithoutRetry(env, port, overrides);
        } catch (IllegalStateException first) {
            if (!first.getMessage().contains("exited") || !first.getMessage().contains("The connection attempt failed")) {
                throw first;
            }
            return startWithoutRetry(env, port, overrides);
        }
    }

    public static BrokerProcess startWithoutRetry(TestEnvironment env, int port, Map<String, String> overrides) {
        Map<String, String> properties = new LinkedHashMap<>();
        env.registerProperties(new DynamicPropertyRegistry() {
            @Override
            public void add(String name, Supplier<Object> valueSupplier) {
                properties.put(name, String.valueOf(valueSupplier.get()));
            }
        });
        properties.put("MCP_BROKER_PORT", String.valueOf(port));
        properties.put("spring.datasource.hikari.maximum-pool-size", "6");
        properties.putAll(overrides);

        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-Xmx256m");
        command.add("-XX:+ExitOnOutOfMemoryError");
        properties.forEach((name, value) -> command.add("-D" + name + "=" + value));
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(BrokerApplication.class.getName());
        try {
            Path log = Files.createTempFile("broker-" + port + "-", ".log");
            Process process = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
            BrokerProcess started = new BrokerProcess(port, process, log);
            started.awaitListening();
            return started;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public int port() {
        return port;
    }

    public boolean alive() {
        return process.isAlive();
    }

    public String output() {
        try {
            return Files.readString(log);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** SIGKILL: no shutdown hook, no graceful drain, connections cut. */
    public void kill() {
        process.destroyForcibly();
        try {
            process.waitFor(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        kill();
    }

    private void awaitListening() {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        while (System.nanoTime() < deadline) {
            if (!process.isAlive()) {
                throw new IllegalStateException("broker on port " + port + " exited: " + output());
            }
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("localhost", port), 500);
                return;
            } catch (IOException e) {
                try {
                    Thread.sleep(250);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(interrupted);
                }
            }
        }
        kill();
        throw new IllegalStateException("broker on port " + port + " did not start: " + output());
    }
}
