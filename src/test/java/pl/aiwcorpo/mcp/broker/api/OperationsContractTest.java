package pl.aiwcorpo.mcp.broker.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.broker.auth.Operation;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import tools.jackson.databind.JsonNode;

/** The operation table of the authentication filter against openapi/credential-broker.v1.yaml (C4). */
class OperationsContractTest {

    /** C4 operations not served before M2-M4; the filter answers them 404. */
    private static final Set<String> NOT_YET_IMPLEMENTED = Set.of(
            "listConnections", "startOAuth", "completeOAuth", "deleteConnection", "purgeUser");

    @Test
    void everyServedOperationHasTheContractMethodPathAndClientCns() {
        Map<String, JsonNode> contract = operations();
        for (Operation operation : Operation.ALL) {
            JsonNode spec = contract.get(operation.operationId());
            assertThat(spec).as(operation.operationId()).isNotNull();
            assertThat(spec.path("method").stringValue()).isEqualTo(operation.method());
            String samplePath = spec.path("path").stringValue().replace("{system}", "jira").replace("{sub}", "x");
            assertThat(operation.path().matcher(samplePath).matches()).as(samplePath).isTrue();
            Set<String> cns = new HashSet<>();
            spec.path("op").path("x-allowed-client-cn").forEach(cn -> cns.add(cn.stringValue()));
            assertThat(operation.allowedCns()).as(operation.operationId()).isEqualTo(cns);
        }
    }

    @Test
    void contractOperationsAreServedOrExplicitlyPending() {
        Set<String> served = new HashSet<>();
        Operation.ALL.forEach(op -> served.add(op.operationId()));
        Set<String> all = new HashSet<>(served);
        all.addAll(NOT_YET_IMPLEMENTED);
        assertThat(operations().keySet()).isEqualTo(all);
    }

    @Test
    void serviceVariantOnlyForListSystems() {
        for (Operation operation : Operation.ALL) {
            assertThat(operation.serviceVariantAllowed()).as(operation.operationId())
                    .isEqualTo("listSystems".equals(operation.operationId()));
        }
        assertThat(operations().get("listSystems").path("op").path("description").stringValue()).contains("service variant");
    }

    private static Map<String, JsonNode> operations() {
        Map<String, JsonNode> result = new HashMap<>();
        JsonNode paths = Contracts.brokerOpenApi().path("paths");
        for (String path : paths.propertyNames()) {
            for (String method : paths.path(path).propertyNames()) {
                JsonNode op = paths.path(path).path(method);
                if (op.has("operationId")) {
                    result.put(op.path("operationId").stringValue(), Contracts.JSON.createObjectNode()
                            .put("method", method.toUpperCase(java.util.Locale.ROOT))
                            .put("path", path)
                            .set("op", op));
                }
            }
        }
        return result;
    }
}
