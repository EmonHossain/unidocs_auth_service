package com.unidocs.auth.audit.application;

import com.unidocs.auth.audit.domain.LoginAuditEnvelope;
import com.unidocs.auth.audit.domain.LogoutAuditEnvelope;
import com.unidocs.auth.audit.domain.LogoutAllAuditEnvelope;
import com.unidocs.auth.audit.domain.RefreshReplayAuditEnvelope;
import com.unidocs.auth.audit.domain.RefreshFailureAuditEnvelope;
import com.unidocs.auth.audit.domain.PasswordResetAuditEnvelope;
import com.unidocs.auth.audit.domain.SecurityAuditEvent;
import com.unidocs.auth.session.persistence.SessionRepository;
import io.micrometer.core.instrument.MeterRegistry;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.json.JsonMapper;

@Component
public class LoginAuditRecorder {
    private final JdbcTemplate jdbc;
    private final JsonMapper json;
    private final MeterRegistry metrics;
    private final String serviceVersion;

    public LoginAuditRecorder(JdbcTemplate jdbc, JsonMapper json, MeterRegistry metrics,
            @Value("${AUTH_SERVICE_VERSION:0.0.1-SNAPSHOT}") String serviceVersion) {
        this.jdbc = jdbc;
        this.json = json;
        this.metrics = metrics;
        this.serviceVersion = serviceVersion;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void record(UUID userId, UUID accountId, UUID sessionId,
            SecurityAuditEvent.Type type, Instant occurredAt) {
        UUID eventId = UUID.randomUUID();
        LoginAuditEnvelope envelope = LoginAuditEnvelope.create(eventId, accountId, sessionId, type,
                occurredAt, MDC.get("requestId"), MDC.get("traceId"), serviceVersion);
        String payload = json.writeValueAsString(envelope);
        persist(eventId, userId, accountId, sessionId, type, occurredAt, payload);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void recordLogout(UUID userId, UUID accountId, UUID sessionId, Instant occurredAt) {
        UUID eventId = UUID.randomUUID();
        LogoutAuditEnvelope envelope = LogoutAuditEnvelope.create(eventId, accountId, sessionId,
                occurredAt, MDC.get("requestId"), MDC.get("traceId"), serviceVersion);
        persist(eventId, userId, accountId, sessionId, SecurityAuditEvent.Type.SESSION_REVOKED,
                occurredAt, json.writeValueAsString(envelope));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void recordRefreshReplay(UUID userId, UUID accountId, UUID sessionId, Instant occurredAt) {
        UUID eventId = UUID.randomUUID();
        RefreshReplayAuditEnvelope envelope = RefreshReplayAuditEnvelope.create(eventId, sessionId,
                occurredAt, MDC.get("requestId"), MDC.get("traceId"), serviceVersion);
        persist(eventId, userId, accountId, sessionId, SecurityAuditEvent.Type.REFRESH_REPLAY,
                occurredAt, json.writeValueAsString(envelope));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void recordLogoutAll(UUID userId, UUID accountId, UUID sessionId, UUID accountGroupId, Instant occurredAt) {
        UUID eventId = UUID.randomUUID();
        LogoutAllAuditEnvelope envelope = LogoutAllAuditEnvelope.create(eventId, accountId, sessionId, accountGroupId,
                occurredAt, MDC.get("requestId"), MDC.get("traceId"), serviceVersion);
        persist(eventId, userId, accountId, sessionId, SecurityAuditEvent.Type.ALL_SESSIONS_REVOKED,
                occurredAt, json.writeValueAsString(envelope));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void recordRefreshFailure(Instant occurredAt) {
        UUID eventId = UUID.randomUUID();
        RefreshFailureAuditEnvelope envelope = RefreshFailureAuditEnvelope.create(eventId,
                occurredAt, MDC.get("requestId"), MDC.get("traceId"), serviceVersion);
        persist(eventId, null, null, null, SecurityAuditEvent.Type.REFRESH_FAILED,
                occurredAt, json.writeValueAsString(envelope));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void recordPasswordReset(UUID userId, UUID accountId, Instant occurredAt) {
        java.util.Objects.requireNonNull(userId, "Affected audit user is required");
        UUID eventId = UUID.randomUUID();
        PasswordResetAuditEnvelope envelope = PasswordResetAuditEnvelope.create(eventId, accountId,
                occurredAt, MDC.get("requestId"), MDC.get("traceId"), serviceVersion);
        persist(eventId, userId, accountId, null, SecurityAuditEvent.Type.PASSWORD_RESET_COMPLETED,
                occurredAt, json.writeValueAsString(envelope));
    }

    private void persist(UUID eventId, UUID userId, UUID accountId, UUID sessionId,
            SecurityAuditEvent.Type type, Instant occurredAt, String payload) {
        try {
            jdbc.update("""
                    INSERT INTO security_audit_event(id,user_id,account_id,session_id,event_type,occurred_at,envelope)
                    VALUES(?,?,?,?,?,?,?)
                    """, SessionRepository.bytes(eventId), SessionRepository.bytes(userId),
                    SessionRepository.bytes(accountId), SessionRepository.bytes(sessionId), type.name(),
                    Timestamp.from(occurredAt), payload);
            jdbc.update("""
                    INSERT INTO outbox_event(id,aggregate_type,aggregate_id,aggregate_version,event_type,
                        payload,status,attempts,created_at,available_at)
                    VALUES(?,'SECURITY_AUDIT',?,1,'SECURITY_AUDIT_RECORDED',?,'PENDING',0,?,?)
                    """, SessionRepository.bytes(eventId), SessionRepository.bytes(eventId), payload,
                    Timestamp.from(occurredAt), Timestamp.from(occurredAt));
        } catch (DataAccessException failure) {
            metrics.counter("audit.persistence", "outcome", "failed").increment();
            throw failure;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                metrics.counter("audit.persistence", "outcome", "committed").increment();
            }
        });
    }
}
