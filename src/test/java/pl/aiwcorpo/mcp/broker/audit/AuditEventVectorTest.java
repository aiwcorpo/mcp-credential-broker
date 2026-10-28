package pl.aiwcorpo.mcp.broker.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.io.Resource;

import pl.aiwcorpo.mcp.broker.support.Contracts;
import tools.jackson.databind.JsonNode;

/** C8 vectors of mcp-contracts 2.2.5: the schema decides, so the broker's own events are held to the same verdicts. */
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
        String backendUser = vector.path("event").path("backendUser").stringValue();
        assertThat(AuditLog.validBackendUser(backendUser)).as(name)
                .isEqualTo(vector.path("expected").path("valid").booleanValue());
    }

    static Stream<Arguments> backendUserVectors() {
        return Contracts.vectors("audit-events").stream()
                .filter(r -> r.getFilename().contains("backend-user") && !r.getFilename().contains("authentication"))
                .map(r -> Arguments.of(r.getFilename(), r));
    }
}
