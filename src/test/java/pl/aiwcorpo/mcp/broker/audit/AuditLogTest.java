package pl.aiwcorpo.mcp.broker.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import pl.aiwcorpo.mcp.broker.support.Contracts;
import tools.jackson.databind.JsonNode;

@ExtendWith(OutputCaptureExtension.class)
class AuditLogTest {

    private final AuditLog audit = new AuditLog("mcp-credential-broker",
            Clock.fixed(Instant.parse("2026-10-27T12:00:00.123Z"), ZoneOffset.UTC));

    @Test
    void lineIsSchemaValidAndCannotBeSplit() {
        String line = audit.serialize(new AuditEvent("2026-10-27T12:00:00.123Z", "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f",
                "broker", "mcp-credential-broker", "connection_change", "sub-1", "jan\u2028{\"forged\":1}\nkowalski\u0000", null,
                "mcp-portal-bff", null, "mcp-jira", null, null, "user-secret", null, "secret_invalid", "denied", null, 3L));

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

    @Test
    void backendUserIsWrittenAndSchemaValid(CapturedOutput output) {
        audit.event("connection_change", "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f")
                .user("sub-1", "alice", "mcp-portal-bff").system("jira").credentialType("user-secret")
                .backendUser("mallory").ok("secret_stored");

        JsonNode line = lastAuditLine(output);
        assertThat(line.path("backendUser").stringValue()).isEqualTo("mallory");
        assertThat(Contracts.schemaErrors("schemas/audit-event.schema.json", line)).isEmpty();
    }

    @Test
    void invalidBackendUserIsOmittedWithAWarningThatDoesNotCarryIt(CapturedOutput output) {
        String[] invalid = {"", "a".repeat(256), "ma\u0000llory", "ma\nllory", "ma\u007fllory", "ma\u0085llory",
                "ma\u2028llory", "ma\u2029llory", "ma\u202ellory", "ma\u2066llory"};
        for (String value : invalid) {
            audit.event("connection_change", "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f").user("sub-1", "alice", null)
                    .system("jira").backendUser(value).ok("secret_stored");
            assertThat(lastAuditLine(output).has("backendUser")).as(value).isFalse();
        }
        assertThat(output.getOut() + output.getErr()).contains("written without backendUser")
                .doesNotContain("mallory");
    }

    @Test
    void backendUserLimitCountsCharactersNotUtf16Units() {
        assertThat(AuditLog.validBackendUser("a".repeat(255))).isTrue();
        assertThat(AuditLog.validBackendUser("\uD83D\uDE00".repeat(255))).isTrue();
        assertThat(AuditLog.validBackendUser("\uD83D\uDE00".repeat(256))).isFalse();
        assertThat(AuditLog.validBackendUser("jan kowalski / zespol")).isTrue();
    }

    private static JsonNode lastAuditLine(CapturedOutput output) {
        String[] lines = output.getAll().split("\n");
        for (int i = lines.length - 1; i >= 0; i--) {
            if (lines[i].startsWith("{") && lines[i].contains("\"component\":\"broker\"")) {
                return Contracts.JSON.readTree(lines[i]);
            }
        }
        throw new AssertionError("no audit line in output");
    }
}
