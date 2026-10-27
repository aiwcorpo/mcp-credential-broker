package pl.aiwcorpo.mcp.broker.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.broker.support.Contracts;
import tools.jackson.databind.JsonNode;

class AuditLogTest {

    private final AuditLog audit = new AuditLog("mcp-credential-broker",
            Clock.fixed(Instant.parse("2026-10-27T12:00:00.123Z"), ZoneOffset.UTC));

    @Test
    void lineIsSchemaValidAndCannotBeSplit() {
        String line = audit.serialize(new AuditEvent("2026-10-27T12:00:00.123Z", "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f",
                "broker", "mcp-credential-broker", "connection_change", "sub-1", "jan\u2028{\"forged\":1}\nkowalski\u0000",
                "mcp-portal-bff", null, "mcp-jira", null, null, "user-secret", null, "identity_mismatch", "denied", null, 3L));

        assertThat(line).doesNotContain("\n", "\r", "\u2028", "\u0000");
        assertThat(line).contains("\\u2028");
        JsonNode parsed = Contracts.JSON.readTree(line);
        assertThat(parsed.path("username").stringValue()).isEqualTo("jan\u2028{\"forged\":1}\nkowalski\u0000");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", parsed)).isEmpty();
    }

    @Test
    void everyFieldIsDefinedByTheContract() {
        JsonNode properties = Contracts.json("schemas/audit-event.schema.json").path("properties");
        for (var component : AuditEvent.class.getRecordComponents()) {
            assertThat(properties.has(component.getName())).as(component.getName()).isTrue();
        }
    }
}
