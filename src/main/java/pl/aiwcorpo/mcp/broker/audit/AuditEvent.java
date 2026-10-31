package pl.aiwcorpo.mcp.broker.audit;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * Audit event (C8, schemas/audit-event.schema.json) as emitted by the broker. The record has no field
 * that could hold a secret or a request body, so none can be logged by mistake. The target system goes
 * into {@code server} as mcp-&lt;system&gt; (CC-009).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"ts", "requestId", "component", "componentId", "event", "sub", "username", "backendUser", "client",
        "server", "tool", "policyRevision", "credentialType", "decision", "reason", "outcome",
        "errorCode", "latencyMs"})
public record AuditEvent(
        String ts,
        String requestId,
        String component,
        String componentId,
        String event,
        String sub,
        String username,
        String backendUser,
        String client,
        String server,
        String tool,
        String policyRevision,
        String credentialType,
        String decision,
        String reason,
        String outcome,
        String errorCode,
        Long latencyMs) {
}
