package pl.aiwcorpo.mcp.broker.support;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import com.sun.net.httpserver.HttpServer;

/** An OTLP/HTTP traces endpoint that keeps the request bodies (protobuf, uncompressed) so a test can search them for text. */
public final class TraceCollectorStub implements AutoCloseable {

    private final HttpServer server;
    private final List<byte[]> bodies = new CopyOnWriteArrayList<>();

    public TraceCollectorStub() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/traces", exchange -> {
            try (exchange) {
                bodies.add(exchange.getRequestBody().readAllBytes());
                exchange.sendResponseHeaders(200, -1);
            }
        });
        server.start();
    }

    public String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/traces";
    }

    public List<byte[]> bodies() {
        return List.copyOf(bodies);
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
