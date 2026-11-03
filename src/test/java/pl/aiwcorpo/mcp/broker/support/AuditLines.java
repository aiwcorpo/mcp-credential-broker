package pl.aiwcorpo.mcp.broker.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.springframework.boot.test.system.CapturedOutput;

import tools.jackson.databind.JsonNode;

/** Broker audit lines (C8) from the captured process output, each checked against audit-event.schema.json. */
public final class AuditLines {

    private AuditLines() {
    }

    public static List<JsonNode> of(CapturedOutput output, String requestId) {
        List<JsonNode> events = all(output).stream().filter(event -> requestId.equals(event.path("requestId").stringValue())).toList();
        for (JsonNode event : events) {
            assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).as(event.toString()).isEmpty();
        }
        return events;
    }

    /** Every broker audit line; the log pattern prefix of a unit test run is cut off. */
    public static List<JsonNode> all(CapturedOutput output) {
        return output.getAll().lines()
                .map(line -> line.indexOf("{\"ts\"") < 0 ? line : line.substring(line.indexOf("{\"ts\"")))
                .filter(line -> line.startsWith("{") && line.contains("\"component\":\"broker\""))
                .map(line -> Contracts.JSON.readTree(line))
                .toList();
    }
}
