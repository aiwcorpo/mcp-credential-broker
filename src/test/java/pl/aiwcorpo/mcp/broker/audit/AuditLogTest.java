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
        String[] invalid = {"", "zqm".repeat(86), "zqm0\u0000", "zqm1\n", "zqm2\u007f", "zqm3\u0085", "zqm4\u2028", "zqm5\u2029",
                "zqm6\u202e", "zqm7\u2066", "zqm8\ud800", "zqm9\udc00x"};
        for (String value : invalid) {
            audit.event("connection_change", "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f").user("sub-1", "alice", null)
                    .system("jira").backendUser(value).ok("secret_stored");
            assertThat(lastAuditLine(output).has("backendUser")).as(value).isFalse();
        }
        String logged = output.getAll();
        assertThat(logged.split("written without backendUser", -1)).hasSize(invalid.length + 1);
        for (String value : invalid) {
            if (!value.isEmpty()) {
                assertThat(logged).as("rejected value must not reach the log").doesNotContain(value);
            }
        }
        assertThat(logged).as("marker carried by every rejected value").doesNotContain("zqm");
    }

    @Test
    void backendUserLimitCountsCharactersNotUtf16Units() {
        assertThat(AuditLog.validBackendUser("a".repeat(255))).isTrue();
        assertThat(AuditLog.validBackendUser("\uD83D\uDE00".repeat(255))).isTrue();
        assertThat(AuditLog.validBackendUser("\uD83D\uDE00".repeat(256))).isFalse();
        assertThat(AuditLog.validBackendUser("jan kowalski / zespol")).isTrue();
        assertThat(AuditLog.validBackendUser("a\ud800b")).as("lone high surrogate").isFalse();
        assertThat(AuditLog.validBackendUser("a\udc00b")).as("lone low surrogate").isFalse();
        assertThat(AuditLog.validBackendUser("a\ud800")).as("trailing high surrogate").isFalse();
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
