package com.unidocs.auth.credential.application;

import java.time.Instant;
import java.sql.Timestamp;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import com.unidocs.auth.session.persistence.SessionRepository;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Caller holds the current account-group fence; all changes share the credential transaction. */
@Component
public class PasswordChangeSecurity {
    private final JdbcTemplate jdbc;
    private final SessionRepository sessions;
    public PasswordChangeSecurity(JdbcTemplate jdbc, SessionRepository sessions) {
        this.jdbc = jdbc;
        this.sessions = sessions;
    }
    public void revoke(UUID accountId, UUID groupId, UUID userId, Instant now) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("Password change revocation requires a transaction.");
        }
        Timestamp timestamp = Timestamp.from(now);
        jdbc.update("""
                INSERT INTO security_audit_event(id,user_id,account_id,session_id,event_type,occurred_at)
                SELECT UUID_TO_BIN(UUID()),?,?,s.id,'SESSION_REVOKED',? FROM user_session s
                WHERE s.account_group_id=? AND s.login_account_id=? AND s.status='ACTIVE'
                """, bytes(userId), bytes(accountId), timestamp, bytes(groupId), bytes(accountId));
        jdbc.update("""
                UPDATE session_refresh_token r JOIN user_session s ON s.id=r.session_id
                SET r.revoked_at=? WHERE s.account_group_id=? AND s.login_account_id=? AND r.revoked_at IS NULL
                """, timestamp, bytes(groupId), bytes(accountId));
        jdbc.update("""
                UPDATE session_account_grant g JOIN user_session s ON s.id=g.session_id
                SET g.status='REVOKED',g.revoked_at=?,g.revocation_reason='CREDENTIAL_CHANGED'
                WHERE s.account_group_id=? AND s.login_account_id=? AND g.status='ACTIVE'
                """, timestamp, bytes(groupId), bytes(accountId));
        jdbc.update("""
                UPDATE user_session SET status='REVOKED',revoked_at=?
                WHERE account_group_id=? AND login_account_id=? AND status='ACTIVE'
                """, timestamp, bytes(groupId), bytes(accountId));
        jdbc.update("""
                UPDATE session_account_grant SET status='REVOKED',revoked_at=?,revocation_reason='CREDENTIAL_CHANGED'
                WHERE account_id=? AND status='ACTIVE'
                """, timestamp, bytes(accountId));
        sessions.reconcileGroup(groupId, now);
    }
}
