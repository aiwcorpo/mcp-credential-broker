package pl.aiwcorpo.mcp.broker.authenticator;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;

import pl.aiwcorpo.mcp.broker.secret.SecretKey;

/**
 * Metadata of authenticators. {@link #lockOrCreate} and {@link #lock} take the row lock that serializes every
 * counter change of one user; they must run inside a transaction.
 */
class AuthenticatorRepository {

    private static final String COLUMNS = """
            sub, state, registration_id, registered_at, last_used_at, last_accepted_step, burned_through, locked_until,
            disabled_at, pending_id, pending_created_at, pending_wrong_codes, enroll_window_start, enroll_starts
            """;

    private final JdbcClient jdbc;

    AuthenticatorRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    Optional<AuthenticatorRecord> find(String sub) {
        return jdbc.sql("select " + COLUMNS + " from authenticator where sub = :sub")
                .param("sub", sub)
                .query(AuthenticatorRepository::map)
                .optional();
    }

    Optional<AuthenticatorRecord> findBySubHash(String hash) {
        return jdbc.sql("select " + COLUMNS + " from authenticator where sub_hash = :hash")
                .param("hash", hash)
                .query(AuthenticatorRepository::map)
                .optional();
    }

    /** Waiting for the row lock is bounded below the statement timeout so that a stuck holder ends in a clear error. */
    Optional<AuthenticatorRecord> lock(String sub) {
        jdbc.sql("set local lock_timeout = '2s'").update();
        return jdbc.sql("select " + COLUMNS + " from authenticator where sub = :sub for update")
                .param("sub", sub)
                .query(AuthenticatorRepository::map)
                .optional();
    }

    AuthenticatorRecord lockOrCreate(String sub, Instant now) {
        jdbc.sql("""
                insert into authenticator (sub, sub_hash, state, updated_at) values (:sub, :hash, 'none', :now)
                on conflict (sub) do nothing
                """)
                .param("sub", sub)
                .param("hash", SecretKey.hashOf(sub))
                .param("now", Timestamp.from(now))
                .update();
        return lock(sub).orElseThrow(() -> new IllegalStateException("authenticator row vanished under its lock"));
    }

    void save(AuthenticatorRecord row, Instant now) {
        jdbc.sql("""
                update authenticator set state = :state, registration_id = :registrationId, registered_at = :registeredAt,
                    last_used_at = :lastUsedAt, last_accepted_step = :lastAcceptedStep, burned_through = :burnedThrough,
                    locked_until = :lockedUntil, disabled_at = :disabledAt, pending_id = :pendingId,
                    pending_created_at = :pendingCreatedAt, pending_wrong_codes = :pendingWrongCodes,
                    enroll_window_start = :enrollWindowStart, enroll_starts = :enrollStarts, updated_at = :now
                where sub = :sub
                """)
                .param("sub", row.sub)
                .param("state", row.state.wire())
                .param("registrationId", row.registrationId)
                .param("registeredAt", timestamp(row.registeredAt))
                .param("lastUsedAt", timestamp(row.lastUsedAt))
                .param("lastAcceptedStep", row.lastAcceptedStep)
                .param("burnedThrough", row.burnedThrough)
                .param("lockedUntil", timestamp(row.lockedUntil))
                .param("disabledAt", timestamp(row.disabledAt))
                .param("pendingId", row.pendingId)
                .param("pendingCreatedAt", timestamp(row.pendingCreatedAt))
                .param("pendingWrongCodes", row.pendingWrongCodes)
                .param("enrollWindowStart", timestamp(row.enrollWindowStart))
                .param("enrollStarts", row.enrollStarts)
                .param("now", Timestamp.from(now))
                .update();
    }

    /** Subs whose enrollment started before {@code cutoff}, oldest first. */
    List<String> findPendingBefore(Instant cutoff, int limit) {
        return jdbc.sql("select sub from authenticator where pending_id is not null and pending_created_at < :cutoff "
                        + "order by pending_created_at limit :limit")
                .param("cutoff", Timestamp.from(cutoff))
                .param("limit", limit)
                .query(String.class)
                .list();
    }

    void addFailure(String sub, Instant at) {
        jdbc.sql("insert into authenticator_failure (sub, at, in_short_window) values (:sub, :at, true)")
                .param("sub", sub)
                .param("at", Timestamp.from(at))
                .update();
    }

    void deleteFailuresBefore(String sub, Instant cutoff) {
        jdbc.sql("delete from authenticator_failure where sub = :sub and at <= :cutoff")
                .param("sub", sub)
                .param("cutoff", Timestamp.from(cutoff))
                .update();
    }

    /** Wrong codes newer than {@code since}; {@code shortWindowOnly} leaves out those a success or a lock already cleared. */
    int countFailures(String sub, Instant since, boolean shortWindowOnly) {
        return jdbc.sql("select count(*) from authenticator_failure where sub = :sub and at > :since"
                        + (shortWindowOnly ? " and in_short_window" : ""))
                .param("sub", sub)
                .param("since", Timestamp.from(since))
                .query(Integer.class)
                .single();
    }

    void clearShortWindow(String sub) {
        jdbc.sql("update authenticator_failure set in_short_window = false where sub = :sub and in_short_window")
                .param("sub", sub)
                .update();
    }

    void deleteFailures(String sub) {
        jdbc.sql("delete from authenticator_failure where sub = :sub").param("sub", sub).update();
    }

    private static Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }

    private static Long number(ResultSet rs, String column) throws SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    private static AuthenticatorRecord map(ResultSet rs, int row) throws SQLException {
        AuthenticatorRecord record = new AuthenticatorRecord(rs.getString("sub"));
        record.state = AuthenticatorRecord.State.fromWire(rs.getString("state"));
        record.registrationId = rs.getString("registration_id");
        record.registeredAt = instant(rs, "registered_at");
        record.lastUsedAt = instant(rs, "last_used_at");
        record.lastAcceptedStep = number(rs, "last_accepted_step");
        record.burnedThrough = number(rs, "burned_through");
        record.lockedUntil = instant(rs, "locked_until");
        record.disabledAt = instant(rs, "disabled_at");
        record.pendingId = rs.getString("pending_id");
        record.pendingCreatedAt = instant(rs, "pending_created_at");
        record.pendingWrongCodes = rs.getInt("pending_wrong_codes");
        record.enrollWindowStart = instant(rs, "enroll_window_start");
        record.enrollStarts = rs.getInt("enroll_starts");
        return record;
    }
}
