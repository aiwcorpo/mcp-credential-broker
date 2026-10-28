package pl.aiwcorpo.mcp.broker.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import pl.aiwcorpo.mcp.broker.support.Contracts;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * C8 vectors of mcp-contracts 2.2.5 against the schema, and the broker's backendUser check against the
 * backendUser vectors. The events the broker really emits are checked in AuditLogTest and the integration tests.
 */
class AuditEventVectorTest {

    static Stream<Arguments> vectors() {
        return Contracts.vectors("audit-events").stream().map(r -> Arguments.of(r.getFilename(), r));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void schemaVerdictMatchesTheVector(String name, Resource file) throws IOException {
        JsonNode vector = Contracts.JSON.readTree(file.getInputStream());
        boolean valid = vector.path("expected").path("valid").booleanValue();
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", vector.path("event")).isEmpty())
                .as(vector.path("description").stringValue()).isEqualTo(valid);
    }

    @Test
    void backendUserVectorsArePresent() {
        assertThat(Contracts.vectors("audit-events")).extracting(Resource::getFilename).contains(
                "broker-connection-change-backend-user.json", "invalid-backend-user-control-char.json",
                "invalid-backend-user-too-long.json", "invalid-authentication-with-backend-user.json");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("backendUserVectors")
    void brokerAgreesWithTheBackendUserVectors(String name, Resource file) throws IOException {
        JsonNode vector = Contracts.JSON.readTree(file.getInputStream());
        assertThat(vector.path("event").has("backendUser")).as(name + " carries backendUser").isTrue();
        String backendUser = vector.path("event").path("backendUser").stringValue();
        assertThat(AuditLog.validBackendUser(backendUser)).as(name)
                .isEqualTo(vector.path("expected").path("valid").booleanValue());
    }

    static Stream<Arguments> backendUserVectors() {
        return Stream.of("broker-connection-change-backend-user.json", "invalid-backend-user-control-char.json",
                        "invalid-backend-user-too-long.json")
                .map(name -> Arguments.of(name, new ClassPathResource(Contracts.ROOT + "test-vectors/audit-events/" + name)));
    }

    @Test
    void longestBackendUserInCodePointsPassesTheSchema() {
        ObjectNode event = (ObjectNode) Contracts.json("test-vectors/audit-events/broker-connection-change-backend-user.json")
                .path("event").deepCopy();
        event.put("backendUser", "\uD83D\uDE00".repeat(255));
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", event)).isEmpty();
        assertThat(AuditLog.validBackendUser(event.path("backendUser").stringValue())).isTrue();
    }
}
