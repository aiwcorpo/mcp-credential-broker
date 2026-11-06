package pl.aiwcorpo.mcp.broker.audit;

import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.aiwcorpo.mcp.broker.system.SystemIds;
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
    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);
    private static final Pattern FORBIDDEN_IN_BACKEND_USER =
            Pattern.compile("[\\p{Cc}\\p{Cf}\\p{Cs}\\u2028\\u2029\\ufdd0-\\ufdef\\ufffe\\uffff\\u034f\\u115f\\u1160\\u3164\\uffa0\\u2800\\ufe00-\\ufe0f]");
    private static final DateTimeFormatter TS = DateTimeFormatter.ISO_INSTANT;

    private final JsonMapper json;
    private volatile Predicate<String> knownSystem = SystemIds::isValid;
    private final String componentId;
    private final Clock clock;

    public AuditLog(String componentId, Clock clock) {
        this.json = JsonMapper.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build();
        this.componentId = componentId;
        this.clock = clock;
    }

    /**
     * The C8 pattern for backendUser (3.0.2): 1..255 characters, none of them a control, format or surrogate
     * character (so also no unpaired surrogate), a line or paragraph separator, a noncharacter, an invisible
     * filler or a variation selector.
     */
    static boolean validBackendUser(String value) {
        int length = value.codePointCount(0, value.length());
        return length >= 1 && length <= 255 && !FORBIDDEN_IN_BACKEND_USER.matcher(value).find();
    }

    /**
     * Which ids the {@code server} field may name: the systems of the table. An id from a request that no system has is not
     * written, so a caller cannot put its own text into the audit log. The broker sets it at start; the default is any valid id, for code that builds an AuditLog alone.
     */
    public void knownSystems(Predicate<String> knownSystem) {
        this.knownSystem = knownSystem;
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
        private String backendUser;
        private String client;
        private String server;
        private String tool;
        private Long policyRevision;
        private String credentialType;
        private String decision;
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

        /**
         * Account in the target system (CC-117), only for connection_change. A value the schema would reject
         * is dropped and the event is written without it; the value stays out of the warning because it
         * came from another system.
         */
        public Entry backendUser(String backendUser) {
            if (backendUser == null) {
                return this;
            }
            if (validBackendUser(backendUser)) {
                this.backendUser = backendUser;
            } else {
                log.warn("Audit event {} (request {}) written without backendUser: value is not valid for C8",
                        event, requestId);
            }
            return this;
        }

        public Entry gatewayContext(String tool, long policyRevision) {
            this.tool = tool;
            this.policyRevision = policyRevision;
            return this;
        }

        /** An id that is not the id of a configured system comes from the caller and is not written (C8 server is a ServerId). */
        public Entry system(String system) {
            this.server = SystemIds.isValid(system) && knownSystem.test(system) ? "mcp-" + system : null;
            return this;
        }

        /** For a system the call itself creates, replaces or removes: valid in shape, and not necessarily in the table. */
        public Entry systemBeingChanged(String system) {
            this.server = SystemIds.isValid(system) ? "mcp-" + system : null;
            return this;
        }

        public Entry credentialType(String credentialType) {
            this.credentialType = credentialType;
            return this;
        }

        /** allow or deny, for events that decide something (the check of a TOTP code, CC-094). */
        public Entry decision(String decision) {
            this.decision = decision;
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
                    componentId, event, sub, username, backendUser, client, server, tool, policyRevision,
                    credentialType, decision, reason, outcome, errorCode,
                    Math.max(0, now.toEpochMilli() - start.toEpochMilli()));
            audit.info(serialize(line));
        }
    }
}
