package pl.aiwcorpo.mcp.broker.audit;

import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import tools.jackson.core.json.JsonWriteFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Writes C8 events as one JSON object per line to the dedicated logger {@code AUDIT} (its own appender,
 * see logback-spring.xml). Non-ASCII is escaped, which covers control characters and U+2028/U+2029 that
 * would otherwise break the line-oriented SIEM format (CC-031).
 */
public class AuditLog {

    public static final String LOGGER = "AUDIT";

    private static final Logger audit = LoggerFactory.getLogger(LOGGER);
    private static final DateTimeFormatter TS = DateTimeFormatter.ISO_INSTANT;

    private final JsonMapper json;
    private final String componentId;
    private final Clock clock;

    public AuditLog(String componentId, Clock clock) {
        this.json = JsonMapper.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build();
        this.componentId = componentId;
        this.clock = clock;
    }

    public Entry event(String event, String requestId) {
        return new Entry(event, requestId, clock.instant());
    }

    public String serialize(AuditEvent event) {
        return json.writeValueAsString(event);
    }

    /** Fluent collector of optional fields; {@link #emit()} writes the line. */
    public final class Entry {

        private final String event;
        private final String requestId;
        private final Instant start;
        private String sub;
        private String username;
        private String client;
        private String virtualServer;
        private String server;
        private String tool;
        private String policyRevision;
        private String credentialType;
        private String reason;
        private String errorCode;

        private Entry(String event, String requestId, Instant start) {
            this.event = event;
            this.requestId = requestId;
            this.start = start;
        }

        public Entry user(String sub, String username, String client) {
            this.sub = sub;
            this.username = username;
            this.client = client;
            return this;
        }

        public Entry gatewayContext(String virtualServer, String tool, String policyRevision) {
            this.virtualServer = virtualServer;
            this.tool = tool;
            this.policyRevision = policyRevision;
            return this;
        }

        /** Unknown system names come from the caller and are not written (C8 server is an enum). */
        public Entry system(String system) {
            this.server = system != null && SystemRegistry.KNOWN_SYSTEMS.contains(system) ? "mcp-" + system : null;
            return this;
        }

        public Entry credentialType(String credentialType) {
            this.credentialType = credentialType;
            return this;
        }

        public void ok(String reason) {
            this.reason = reason;
            emit("ok");
        }

        public void denied(String reason, String errorCode) {
            this.reason = reason;
            this.errorCode = errorCode;
            emit("denied");
        }

        public void error(String reason, String errorCode) {
            this.reason = reason;
            this.errorCode = errorCode;
            emit("error");
        }

        private void emit(String outcome) {
            Instant now = clock.instant();
            AuditEvent line = new AuditEvent(TS.format(now.truncatedTo(ChronoUnit.MILLIS)), requestId, "broker",
                    componentId, event, sub, username, client, virtualServer, server, tool, policyRevision,
                    credentialType, null, reason, outcome, errorCode,
                    Math.max(0, now.toEpochMilli() - start.toEpochMilli()));
            audit.info(serialize(line));
        }
    }
}
