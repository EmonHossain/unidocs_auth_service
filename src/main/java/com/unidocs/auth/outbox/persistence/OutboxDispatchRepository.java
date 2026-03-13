package com.unidocs.auth.outbox.persistence;

import com.unidocs.auth.outbox.domain.ClaimedOutboxEvent;
import java.nio.ByteBuffer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Repository
@Transactional(propagation = Propagation.REQUIRES_NEW)
public class OutboxDispatchRepository {
    private final JdbcTemplate jdbc;

    public OutboxDispatchRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<ClaimedOutboxEvent> claim(int limit, Duration lease) {
        if (limit < 1 || limit > 100 || lease.isNegative() || lease.isZero()) {
            throw new IllegalArgumentException("Invalid outbox claim bounds.");
        }
        UUID token = UUID.randomUUID();
        List<ClaimedOutboxEvent> events = jdbc.query("""
                SELECT id, aggregate_type, aggregate_id, aggregate_version, event_type,
                       payload, created_at, attempts
                FROM outbox_event
                WHERE status='PENDING' AND available_at <= UTC_TIMESTAMP(6)
                  AND (lease_until IS NULL OR lease_until <= UTC_TIMESTAMP(6))
                ORDER BY available_at, created_at, id LIMIT ? FOR UPDATE SKIP LOCKED
                """, (rs, row) -> event(rs, token), limit);
        for (ClaimedOutboxEvent event : events) {
            jdbc.update("""
                    UPDATE outbox_event SET claim_token=?,
                        lease_until=TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6)), attempts=?
                    WHERE id=?
                    """, bytes(token), lease.toNanos() / 1000, event.attempts(), bytes(event.id()));
        }
        return List.copyOf(events);
    }

    /** Renew just before sending; expired reservations are skipped and recovered on a later poll. */
    public boolean renew(ClaimedOutboxEvent event, Duration lease) {
        return jdbc.update("""
                UPDATE outbox_event SET lease_until=TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6))
                WHERE id=? AND status='PENDING' AND claim_token=? AND lease_until > UTC_TIMESTAMP(6)
                """, lease.toNanos() / 1000, bytes(event.id()), bytes(event.claimToken())) == 1;
    }

    public boolean published(ClaimedOutboxEvent event) {
        return jdbc.update("""
                UPDATE outbox_event SET status='PUBLISHED', published_at=UTC_TIMESTAMP(6),
                    claim_token=NULL, lease_until=NULL, last_error=NULL
                WHERE id=? AND status='PENDING' AND claim_token=? AND lease_until > UTC_TIMESTAMP(6)
                """, bytes(event.id()), bytes(event.claimToken())) == 1;
    }

    public boolean retry(ClaimedOutboxEvent event, Duration delay) {
        return jdbc.update("""
                UPDATE outbox_event SET available_at=TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6)),
                    claim_token=NULL, lease_until=NULL, last_error='KAFKA_PUBLISH_FAILED'
                WHERE id=? AND status='PENDING' AND claim_token=? AND lease_until > UTC_TIMESTAMP(6)
                """, delay.toNanos() / 1000, bytes(event.id()), bytes(event.claimToken())) == 1;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW, readOnly = true)
    public Optional<Instant> oldestPending() {
        return jdbc.query("""
                SELECT created_at FROM outbox_event WHERE status='PENDING'
                ORDER BY created_at, id LIMIT 1
                """, (rs, row) -> rs.getTimestamp("created_at").toInstant()).stream().findFirst();
    }

    /** Includes leased events and retries waiting for their next available time. */
    @Transactional(propagation = Propagation.REQUIRES_NEW, readOnly = true)
    public long pendingCount() {
        return jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE status='PENDING'", Long.class);
    }
    private static ClaimedOutboxEvent event(ResultSet rs, UUID token) throws SQLException {
        int attempts = rs.getInt("attempts");
        return new ClaimedOutboxEvent(id(rs, "id"), rs.getString("aggregate_type"), id(rs, "aggregate_id"),
                rs.getLong("aggregate_version"), rs.getString("event_type"), rs.getString("payload"),
                rs.getTimestamp("created_at").toInstant(), attempts == Integer.MAX_VALUE ? attempts : attempts + 1, token);
    }

    private static UUID id(ResultSet rs, String column) throws SQLException {
        ByteBuffer buffer = ByteBuffer.wrap(rs.getBytes(column));
        return new UUID(buffer.getLong(), buffer.getLong());
    }
}
