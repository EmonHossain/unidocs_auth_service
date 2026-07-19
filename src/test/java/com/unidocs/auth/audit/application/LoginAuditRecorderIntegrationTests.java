package com.unidocs.auth.audit.application;

import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.audit.domain.SecurityAuditEvent;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doThrow;

@SpringBootTest
class LoginAuditRecorderIntegrationTests extends MySqlIntegrationTest {
    @Autowired LoginAuditRecorder recorder;
    @Autowired PlatformTransactionManager transactions;
    @Autowired JsonMapper json;
    @Autowired MeterRegistry metrics;
    @MockitoSpyBean JdbcTemplate observedJdbc;

    @Test
    void commitsMatchingAuditAndOutboxWithOnlySafeCorrelation() {
        UUID account = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        String requestId = UUID.randomUUID().toString();
        MDC.put("requestId", requestId);
        MDC.put("traceId", "4bf92f3577b34da6a3ce929d0e0e4736");
        MDC.put("password", "do-not-export-password");
        MDC.put("tenantId", UUID.randomUUID().toString());
        try {
            new TransactionTemplate(transactions).executeWithoutResult(status ->
                    recorder.record(UUID.randomUUID(), account, session, SecurityAuditEvent.Type.LOGIN_SUCCEEDED, Instant.now()));
        } finally {
            MDC.clear();
        }
        String audit = jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class);
        String payload = jdbc.queryForObject("SELECT payload FROM outbox_event", String.class);
        assertThat(json.readTree(payload)).isEqualTo(json.readTree(audit));
        JsonNode envelope = json.readTree(payload);
        assertThat(envelope.path("actorId").asString()).isEqualTo(account.toString());
        assertThat(envelope.path("targetId").asString()).isEqualTo(session.toString());
        assertThat(envelope.path("requestId").asString()).isEqualTo(requestId);
        assertThat(envelope.path("schemaVersion").asInt()).isEqualTo(1);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM outbox_event o JOIN security_audit_event a ON a.id=o.id
                WHERE o.aggregate_type='SECURITY_AUDIT' AND o.aggregate_id=a.id AND o.aggregate_version=1
                    AND o.status='PENDING' AND o.event_type='SECURITY_AUDIT_RECORDED'
                """, Integer.class)).isEqualTo(1);
        assertThat(payload).doesNotContain("do-not-export-password", "tenantId", "password", "email");
    }

    @Test
    void unknownFailedLoginCommitsWithoutClaimingActorIdentity() {
        new TransactionTemplate(transactions).executeWithoutResult(status ->
                recorder.record(null, null, null, SecurityAuditEvent.Type.LOGIN_FAILED, Instant.now()));
        JsonNode envelope = json.readTree(jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class));
        assertThat(envelope.path("actorType").asString()).isEqualTo("UNKNOWN");
        assertThat(envelope.path("actorId").isNull()).isTrue();
        assertThat(envelope.path("outcome").asString()).isEqualTo("FAILURE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event", Integer.class)).isEqualTo(1);
    }

    @Test
    void requiresCallerTransaction() {
        assertThatThrownBy(() -> recorder.recordPasswordReset(UUID.randomUUID(), UUID.randomUUID(), Instant.now()))
                .isInstanceOf(IllegalTransactionStateException.class);
        assertThatThrownBy(() -> recorder.recordRefreshFailure(Instant.now()))
                .isInstanceOf(IllegalTransactionStateException.class);
        assertThatThrownBy(() -> recorder.recordLogoutAll(null, UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), Instant.now()))
                .isInstanceOf(IllegalTransactionStateException.class);
        assertThatThrownBy(() -> recorder.recordRefreshReplay(null, UUID.randomUUID(), UUID.randomUUID(), Instant.now()))
                .isInstanceOf(IllegalTransactionStateException.class);
        assertThatThrownBy(() -> recorder.recordLogout(null, UUID.randomUUID(), UUID.randomUUID(), Instant.now()))
                .isInstanceOf(IllegalTransactionStateException.class);
        assertThatThrownBy(() -> recorder.record(null, null, null, SecurityAuditEvent.Type.LOGIN_FAILED, Instant.now()))
                .isInstanceOf(IllegalTransactionStateException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event", Integer.class)).isZero();
    }

    @ParameterizedTest
    @ValueSource(strings = {"actorId", "targetId", "sessionId"})
    void databaseRejectsPasswordResetEnvelopeForgingIdentityOrRemovingRequiredFacts(String field) {
        new TransactionTemplate(transactions).executeWithoutResult(status ->
                recorder.recordPasswordReset(UUID.randomUUID(), UUID.randomUUID(), Instant.now()));
        String envelope = jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class);
        assertThatThrownBy(() -> jdbc.update("UPDATE security_audit_event SET envelope=JSON_SET(envelope,?,?)",
                "$." + field, UUID.randomUUID().toString()))
                .isInstanceOf(org.springframework.dao.DataAccessException.class)
                .hasMessageContaining("chk_security_audit_envelope");
        assertThatThrownBy(() -> jdbc.update("UPDATE security_audit_event SET envelope=JSON_REMOVE(envelope,?)", "$." + field))
                .isInstanceOf(org.springframework.dao.DataAccessException.class)
                .hasMessageContaining("chk_security_audit_envelope");
        assertThat(jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class)).isEqualTo(envelope);
    }

    @Test
    void databaseRejectsLogoutEnvelopeThatChangesTheVerifiedActor() {
        UUID accountId = UUID.randomUUID();
        new TransactionTemplate(transactions).executeWithoutResult(status ->
                recorder.recordLogout(null, accountId, UUID.randomUUID(), Instant.now()));
        String envelope = jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class);
        String forged = envelope.replace(accountId.toString(), UUID.randomUUID().toString());
        assertThatThrownBy(() -> jdbc.update("UPDATE security_audit_event SET envelope=?", forged))
                .isInstanceOf(org.springframework.dao.DataAccessException.class)
                .hasRootCauseInstanceOf(java.sql.SQLException.class)
                .hasMessageContaining("chk_security_audit_envelope");
        assertThat(jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class)).isEqualTo(envelope);
    }
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void outboxFailureRollsBackAuditAndBusinessMutation(boolean logout) {
        doThrow(new DataIntegrityViolationException("test-only")).when(observedJdbc)
                .update(startsWith("INSERT INTO outbox_event"), any(Object[].class));
        long version = jdbc.queryForObject("SELECT version FROM session_grant_policy", Long.class);
        double failures = metrics.counter("audit.persistence", "outcome", "failed").count();
        double committed = metrics.counter("audit.persistence", "outcome", "committed").count();
        assertThatThrownBy(() -> new TransactionTemplate(transactions).executeWithoutResult(status -> {
            jdbc.update("UPDATE session_grant_policy SET version=version+1");
            if (logout) {
                recorder.recordLogout(null, UUID.randomUUID(), UUID.randomUUID(), Instant.now());
            } else {
                recorder.record(null, null, null, SecurityAuditEvent.Type.LOGIN_FAILED, Instant.now());
            }
        })).isInstanceOf(DataIntegrityViolationException.class);
        assertThat(jdbc.queryForObject("SELECT version FROM session_grant_policy", Long.class)).isEqualTo(version);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event", Integer.class)).isZero();
        assertThat(metrics.counter("audit.persistence", "outcome", "failed").count()).isEqualTo(failures + 1);
        assertThat(metrics.counter("audit.persistence", "outcome", "committed").count()).isEqualTo(committed);
    }

    @Test
    void refreshReplayCommitsUnknownActorAndMatchingSessionOutbox() {
        UUID session = UUID.randomUUID();
        String requestId = UUID.randomUUID().toString();
        try {
            new TransactionTemplate(transactions).executeWithoutResult(status -> {
                MDC.put("requestId", requestId);
                MDC.put("traceId", "4bf92f3577b34da6a3ce929d0e0e4736");
                MDC.put("password", "do-not-export-refresh-secret");
                recorder.recordRefreshReplay(UUID.randomUUID(), UUID.randomUUID(), session, Instant.now());
            });
        } finally {
            MDC.clear();
        }
        String audit = jdbc.queryForObject("SELECT envelope FROM security_audit_event WHERE event_type='REFRESH_REPLAY'", String.class);
        String payload = jdbc.queryForObject("SELECT payload FROM outbox_event WHERE aggregate_type='SECURITY_AUDIT'", String.class);
        JsonNode envelope = json.readTree(audit);
        assertThat(json.readTree(payload)).isEqualTo(envelope);
        assertThat(envelope.path("schemaVersion").asInt()).isEqualTo(1);
        assertThat(envelope.path("actorType").asText()).isEqualTo("UNKNOWN");
        assertThat(envelope.path("actorId").isNull()).isTrue();
        assertThat(envelope.path("targetId").asText()).isEqualTo(session.toString());
        assertThat(envelope.path("requestId").asText()).isEqualTo(requestId);
        assertThat(envelope.path("traceId").asText()).isEqualTo("4bf92f3577b34da6a3ce929d0e0e4736");
        assertThat(payload).doesNotContain("do-not-export-refresh-secret", "password", "email");
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM outbox_event o JOIN security_audit_event a ON a.id=o.id
                WHERE a.event_type='REFRESH_REPLAY' AND o.aggregate_type='SECURITY_AUDIT'
                  AND o.aggregate_id=a.id AND o.aggregate_version=1 AND o.status='PENDING'
                  AND o.event_type='SECURITY_AUDIT_RECORDED'
                """, Integer.class)).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"actorId", "targetId"})
    void databaseRejectsReplayEnvelopeForgingActorOrTarget(String field) {
        new TransactionTemplate(transactions).executeWithoutResult(status ->
                recorder.recordRefreshReplay(null, UUID.randomUUID(), UUID.randomUUID(), Instant.now()));
        String envelope = jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class);
        assertThatThrownBy(() -> jdbc.update("UPDATE security_audit_event SET envelope=JSON_SET(envelope,?,?)",
                "$." + field, UUID.randomUUID().toString()))
                .isInstanceOf(org.springframework.dao.DataAccessException.class)
                .hasMessageContaining("chk_security_audit_envelope");
        assertThat(jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class)).isEqualTo(envelope);
    }

    @ParameterizedTest
    @ValueSource(strings = {"actorId", "targetId", "sessionId"})
    void databaseRejectsUnprovenRefreshFailureClaimingIdentity(String field) {
        new TransactionTemplate(transactions).executeWithoutResult(status ->
                recorder.recordRefreshFailure(Instant.now()));
        String envelope = jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class);
        assertThatThrownBy(() -> jdbc.update("UPDATE security_audit_event SET envelope=JSON_SET(envelope,?,?)",
                "$." + field, UUID.randomUUID().toString()))
                .isInstanceOf(org.springframework.dao.DataAccessException.class)
                .hasMessageContaining("chk_security_audit_envelope");
        assertThat(jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class)).isEqualTo(envelope);
    }

    @Test
    void logoutAllCommitsVerifiedActorGroupAndMatchingOutbox() {
        UUID account = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        UUID group = UUID.randomUUID();
        String requestId = UUID.randomUUID().toString();
        try {
            new TransactionTemplate(transactions).executeWithoutResult(status -> {
                MDC.put("requestId", requestId);
                MDC.put("traceId", "4bf92f3577b34da6a3ce929d0e0e4736");
                MDC.put("password", "do-not-export-all-device-secret");
                recorder.recordLogoutAll(UUID.randomUUID(), account, session, group, Instant.now());
            });
        } finally {
            MDC.clear();
        }
        String audit = jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class);
        String payload = jdbc.queryForObject("SELECT payload FROM outbox_event", String.class);
        JsonNode envelope = json.readTree(audit);
        assertThat(json.readTree(payload)).isEqualTo(envelope);
        assertThat(envelope.path("reasonCode").asText()).isEqualTo("LOGOUT_ALL");
        assertThat(envelope.path("actorId").asText()).isEqualTo(account.toString());
        assertThat(envelope.path("sessionId").asText()).isEqualTo(session.toString());
        assertThat(envelope.path("targetId").asText()).isEqualTo(group.toString());
        assertThat(envelope.path("accountGroupId").asText()).isEqualTo(group.toString());
        assertThat(envelope.path("requestId").asText()).isEqualTo(requestId);
        assertThat(envelope.path("traceId").asText()).isEqualTo("4bf92f3577b34da6a3ce929d0e0e4736");
        assertThat(payload).doesNotContain("do-not-export-all-device-secret", "password", "email");
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM outbox_event o JOIN security_audit_event a ON a.id=o.id
                WHERE a.event_type='ALL_SESSIONS_REVOKED' AND o.aggregate_type='SECURITY_AUDIT'
                  AND o.aggregate_id=a.id AND o.aggregate_version=1 AND o.status='PENDING'
                  AND o.event_type='SECURITY_AUDIT_RECORDED'
                """, Integer.class)).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"actorId", "targetId", "accountGroupId"})
    void databaseRejectsLogoutAllEnvelopeForgingActorOrGroup(String field) {
        new TransactionTemplate(transactions).executeWithoutResult(status ->
                recorder.recordLogoutAll(null, UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), Instant.now()));
        String envelope = jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class);
        assertThatThrownBy(() -> jdbc.update("UPDATE security_audit_event SET envelope=JSON_SET(envelope,?,?)",
                "$." + field, UUID.randomUUID().toString()))
                .isInstanceOf(org.springframework.dao.DataAccessException.class)
                .hasMessageContaining("chk_security_audit_envelope");
        assertThatThrownBy(() -> jdbc.update("UPDATE security_audit_event SET envelope=JSON_REMOVE(envelope,?)", "$." + field))
                .isInstanceOf(org.springframework.dao.DataAccessException.class)
                .hasMessageContaining("chk_security_audit_envelope");
        assertThat(jdbc.queryForObject("SELECT envelope FROM security_audit_event", String.class)).isEqualTo(envelope);
    }
}
