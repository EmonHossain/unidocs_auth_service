package com.unidocs.auth.session.persistence;

import java.nio.ByteBuffer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import com.unidocs.auth.organization.persistence.OrganizationAccountScope;
import com.unidocs.auth.session.domain.*;
import com.unidocs.auth.session.domain.SessionGrantPolicy;

/** Explicit JDBC mappings keep the session lock and refresh-family updates in one transaction. */
@Repository
public class SessionRepository {
    private final JdbcTemplate jdbc;
    private final com.unidocs.auth.audit.application.LoginAuditRecorder loginAudits;
    public SessionRepository(JdbcTemplate jdbc, com.unidocs.auth.audit.application.LoginAuditRecorder loginAudits) {
        this.jdbc = jdbc;
        this.loginAudits = loginAudits;
    }

    public record Identity(UUID id, UUID accountId, UUID userId, UUID groupId, UUID preferredAccountId,
            String displayName, String passwordHash, long credentialVersion, boolean available) {
        @Override public String toString() { return "Identity[REDACTED]"; }
    }
    public record Refresh(UUID id, UUID sessionId, String secretHash, Instant expiresAt, Instant usedAt, Instant revokedAt) {
        @Override public String toString() { return "Refresh[REDACTED]"; }
    }
    public record Account(UUID id, String displayName, String type, boolean unlocked) { }
    public record Owner(UUID userId, String displayName, UUID preferredAccountId) { }

    public SessionGrantPolicy policy() {
        return jdbc.queryForObject("SELECT * FROM session_grant_policy WHERE scope_type = 'GLOBAL'", (rs, row) ->
                new SessionGrantPolicy(java.time.Duration.ofSeconds(rs.getInt("idle_timeout_seconds")),
                        java.time.Duration.ofSeconds(rs.getInt("absolute_timeout_seconds")), rs.getLong("version")));
    }

    public Optional<UUID> sessionGroup(UUID sessionId) {
        return jdbc.query("SELECT account_group_id FROM user_session WHERE id=?", (rs,n)->id(rs,"account_group_id"), bytes(sessionId)).stream().findFirst();
    }
    public void lockGroup(UUID groupId) {
        if (jdbc.query("SELECT id FROM account_group WHERE id=? FOR UPDATE",(rs,n)->id(rs,"id"),bytes(groupId)).isEmpty())
            throw new com.unidocs.auth.authentication.application.AuthenticationFailure();
    }
    public Optional<Owner> owner(UUID groupId) {
        return jdbc.query("""
            SELECT u.id, u.display_name, p.preferred_account_id FROM account_group g
            JOIN users u ON u.id = g.user_id JOIN user_preference p ON p.user_id = u.id
            WHERE g.id = ? AND g.status = 'ACTIVE' AND u.status = 'ACTIVE' FOR UPDATE
            """, (rs, row) -> new Owner(id(rs, "id"), rs.getString("display_name"), id(rs, "preferred_account_id")),
                bytes(groupId)).stream().findFirst();
    }

    private static final String LIVE_GRANT = """
        SELECT sg.* FROM session_account_grant sg
        JOIN user_account a ON a.id = sg.account_id
        JOIN account_group_member m ON m.account_id = a.id
        JOIN account_group g ON g.id = m.account_group_id
        JOIN users u ON u.id = g.user_id
        JOIN session_grant_policy p ON p.scope_type = 'GLOBAL'
        LEFT JOIN login_identity li ON sg.credential_source = 'LOGIN_IDENTITY' AND li.id = sg.credential_id AND li.account_id = a.id
        LEFT JOIN account_credential ac ON sg.credential_source = 'ACCOUNT_CREDENTIAL' AND ac.id = sg.credential_id AND ac.account_id = a.id
        WHERE sg.session_id = ? AND m.account_group_id = ? AND m.status = 'LINKED'
            AND a.user_id = g.user_id AND a.status = 'ACTIVE' AND g.status = 'ACTIVE' AND u.status = 'ACTIVE'
            AND sg.status = 'ACTIVE' AND sg.idle_expires_at > ? AND sg.absolute_expires_at > ?
            AND sg.policy_version = p.version
            AND ((li.status = 'ACTIVE' AND li.credential_version = sg.credential_version)
                OR (ac.status = 'ACTIVE' AND ac.version = sg.credential_version))
        """ + " AND " + OrganizationAccountScope.GRANT;

    public Optional<SessionAccountGrant> liveGrant(UserSession session, UUID accountId, Instant now) {
        return jdbc.query(LIVE_GRANT + (accountId == null ? "" : " AND sg.account_id = ?")
                        + " ORDER BY (sg.auth_method = 'LOGIN') DESC, sg.account_id LIMIT 1 FOR UPDATE",
                this::mapGrant, accountId == null
                    ? new Object[]{bytes(session.id()), bytes(session.accountGroupId()), time(now), time(now)}
                    : new Object[]{bytes(session.id()), bytes(session.accountGroupId()), time(now), time(now), bytes(accountId)})
                .stream().findFirst();
    }

    /** Selected-account classification under the caller's existing account-group fence. */
    public Optional<String> accountType(UserSession session, UUID accountId) {
        return jdbc.query("""
            SELECT a.type FROM user_account a
            JOIN account_group_member m ON m.account_id=a.id
            WHERE a.id=? AND m.account_group_id=? AND m.status='LINKED' AND a.status='ACTIVE'
            """, (result, row) -> result.getString(1), bytes(accountId), bytes(session.accountGroupId()))
                .stream().findFirst();
    }

    private SessionAccountGrant mapGrant(ResultSet rs, int row) throws SQLException {
        return new SessionAccountGrant(id(rs, "session_id"), id(rs, "account_id"), rs.getString("status"), rs.getString("auth_method"),
                rs.getLong("credential_version"), instant(rs, "idle_expires_at"), instant(rs, "absolute_expires_at"));
    }

    private static final String IDENTITY_SQL = """
        SELECT i.id, i.account_id, a.user_id, g.id AS group_id, p.preferred_account_id,
            u.display_name, i.password_hash, i.credential_version,
            (i.status = 'ACTIVE' AND a.status = 'ACTIVE' AND u.status = 'ACTIVE'
                AND m.status = 'LINKED' AND g.status = 'ACTIVE' AND g.user_id = a.user_id AND %s) AS available
        FROM login_identity i JOIN user_account a ON a.id = i.account_id
        JOIN users u ON u.id = a.user_id JOIN user_preference p ON p.user_id = u.id
        JOIN account_group_member m ON m.account_id = a.id JOIN account_group g ON g.id = m.account_group_id
        WHERE i.type IN ('EMAIL','ACCOUNT_ID')
        """.formatted(OrganizationAccountScope.PASSWORD);

    public Optional<Identity> identity(String email, boolean lock) {
        return jdbc.query(IDENTITY_SQL + " AND i.type='EMAIL' AND i.identifier = ?" + (lock ? " FOR UPDATE" : ""),
                this::identity, email).stream().findFirst();
    }

    public Optional<Identity> accountIdentity(UUID accountId) {
        return jdbc.query(IDENTITY_SQL + " AND i.account_id = ? FOR UPDATE", this::identity, bytes(accountId))
                .stream().findFirst();
    }

    public Optional<Identity> organizationIdentity(UUID accountId, boolean lock) {
        return jdbc.query(IDENTITY_SQL + " AND i.type='ACCOUNT_ID' AND a.organization_id IS NOT NULL AND i.account_id=?"
                + (lock ? " FOR UPDATE" : ""),this::identity,bytes(accountId)).stream().findFirst();
    }

    private Identity identity(ResultSet rs, int row) throws SQLException {
        return new Identity(id(rs, "id"), id(rs, "account_id"), id(rs, "user_id"), id(rs, "group_id"),
                id(rs, "preferred_account_id"), rs.getString("display_name"), rs.getString("password_hash"),
                rs.getLong("credential_version"), rs.getBoolean("available"));
    }

    public void create(UserSession session, Identity identity, RefreshSecret secret, Instant now) {
        SessionGrantPolicy policy = policy();
        Instant absolute = policy.absoluteExpiry(now, session);
        jdbc.update("""
            INSERT INTO user_session (id, account_group_id, login_account_id, status, authenticated_at, last_activity_at, expires_at)
            VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?)
            """, bytes(session.id()), bytes(session.accountGroupId()), bytes(session.loginAccountId()), time(now), time(now), time(session.expiresAt()));
        jdbc.update("""
            INSERT INTO session_account_grant (id, session_id, account_id, status, auth_method, credential_version,
                authenticated_at, last_activity_at, idle_expires_at, absolute_expires_at, credential_id, policy_version)
            VALUES (?, ?, ?, 'ACTIVE', 'LOGIN', ?, ?, ?, ?, ?, ?, ?)
            """, bytes(UUID.randomUUID()), bytes(session.id()), bytes(identity.accountId()), identity.credentialVersion(),
                time(now), time(now), time(policy.idleExpiry(now, absolute)), time(absolute), bytes(identity.id()), policy.version());
        insertRefresh(secret, session, now);
        jdbc.update("UPDATE login_identity SET last_authenticated_at = ?, updated_at = ? WHERE id = ?", time(now), time(now), bytes(identity.id()));
        jdbc.update("UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?", time(now), time(now), bytes(identity.userId()));
    }

    public Optional<UserSession> lock(UUID sessionId) {
        return jdbc.query("SELECT * FROM user_session WHERE id = ? FOR UPDATE", (rs, row) ->
                new UserSession(id(rs, "id"), id(rs, "account_group_id"), id(rs, "login_account_id"), rs.getString("status"),
                    instant(rs, "authenticated_at"), instant(rs, "last_activity_at"), instant(rs, "expires_at"), instant(rs, "revoked_at")),
                bytes(sessionId)).stream().findFirst();
    }

    public Optional<SessionAccountGrant> grant(UUID sessionId, UUID accountId) {
        return jdbc.query("SELECT * FROM session_account_grant WHERE session_id = ? AND account_id = ? FOR UPDATE", (rs, row) ->
                new SessionAccountGrant(id(rs, "session_id"), id(rs, "account_id"), rs.getString("status"), rs.getString("auth_method"),
                    rs.getLong("credential_version"), instant(rs, "idle_expires_at"), instant(rs, "absolute_expires_at")),
                bytes(sessionId), bytes(accountId)).stream().findFirst();
    }

    public Optional<UUID> refreshSession(UUID tokenId) {
        return jdbc.query("SELECT session_id FROM session_refresh_token WHERE id = ?", (rs, row) -> id(rs, "session_id"),
                bytes(tokenId)).stream().findFirst();
    }

    public Optional<Refresh> refresh(UUID tokenId) {
        return jdbc.query("SELECT * FROM session_refresh_token WHERE id = ? FOR UPDATE", (rs, row) ->
                new Refresh(id(rs, "id"), id(rs, "session_id"), rs.getString("secret_hash"), instant(rs, "expires_at"),
                    instant(rs, "used_at"), instant(rs, "revoked_at")), bytes(tokenId)).stream().findFirst();
    }

    private void insertRefresh(RefreshSecret secret, UserSession session, Instant now) {
        jdbc.update("INSERT INTO session_refresh_token (id, session_id, secret_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                bytes(secret.id()), bytes(session.id()), secret.hash(), time(now), time(session.expiresAt()));
    }

    public void rotate(Refresh old, RefreshSecret replacement, UserSession session, Instant now) {
        insertRefresh(replacement, session, now);
        jdbc.update("UPDATE session_refresh_token SET used_at = ?, replaced_by_id = ? WHERE id = ?",
                time(now), bytes(replacement.id()), bytes(old.id()));
    }

    /**
     * Records accepted activity without letting an older context shorten a completion-guarded deadline.
     * @param session current locked session
     * @param grant current selected account grant
     * @param now accepted activity time, which may precede a later authorization revalidation touch
     */
    public void touch(UserSession session, SessionAccountGrant grant, Instant now) {
        jdbc.update("UPDATE user_session SET last_activity_at = GREATEST(last_activity_at, ?) WHERE id = ?", time(now), bytes(session.id()));
        jdbc.update("UPDATE session_account_grant SET last_activity_at = GREATEST(last_activity_at, ?), idle_expires_at = GREATEST(idle_expires_at, ?) WHERE session_id = ? AND account_id = ?",
                time(now), time(policy().idleExpiry(now, grant.absoluteExpiresAt())), bytes(session.id()), bytes(grant.accountId()));
    }

    public void revoke(UserSession session, Identity identity, Instant now, String reason) {
        if ("REVOKED".equals(session.status())) return;
        jdbc.update("UPDATE user_session SET status = 'REVOKED', revoked_at = ? WHERE id = ?", time(now), bytes(session.id()));
        jdbc.update("UPDATE session_account_grant SET status = 'REVOKED', revoked_at = ?, revocation_reason = ? WHERE session_id = ? AND status = 'ACTIVE'",
                time(now), reason, bytes(session.id()));
        jdbc.update("UPDATE session_refresh_token SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL", time(now), bytes(session.id()));
        if ("LOGOUT".equals(reason)) {
            loginAudits.recordLogout(identity == null ? null : identity.userId(),
                    session.loginAccountId(), session.id(), now);
        } else {
            audit(identity, session.id(), "SESSION_REVOKED", now);
        }
    }

    /** The caller's account-group fence serializes login, refresh and grant mutations. */
    public void revokeGroup(UUID groupId, Instant now) {
        jdbc.update("""
            INSERT INTO security_audit_event (id, user_id, account_id, session_id, event_type, occurred_at)
            SELECT UUID_TO_BIN(UUID()), g.user_id, s.login_account_id, s.id, 'SESSION_REVOKED', ?
            FROM user_session s JOIN account_group g ON g.id = s.account_group_id
            WHERE s.account_group_id = ? AND s.status = 'ACTIVE'
            """, time(now), bytes(groupId));
        jdbc.update("""
            UPDATE user_session SET status = 'REVOKED', revoked_at = ?
            WHERE account_group_id = ? AND status = 'ACTIVE'
            """, time(now), bytes(groupId));
        jdbc.update("""
            UPDATE session_refresh_token r JOIN user_session s ON s.id = r.session_id
            SET r.revoked_at = ? WHERE s.account_group_id = ? AND r.revoked_at IS NULL
            """, time(now), bytes(groupId));
        jdbc.update("""
            UPDATE session_account_grant sg JOIN user_session s ON s.id = sg.session_id
            SET sg.status = 'REVOKED', sg.revoked_at = ?, sg.revocation_reason = 'LOGOUT'
            WHERE s.account_group_id = ? AND sg.status = 'ACTIVE'
            """, time(now), bytes(groupId));
    }

    /** Caller holds the account-group fence; avoid a query per historical session. */
    public void reconcileGroup(UUID group,Instant now) {
        String usable=LIVE_GRANT.replace("SELECT sg.*","SELECT 1")
                .replace("sg.session_id = ? AND m.account_group_id = ?","sg.session_id = s.id AND m.account_group_id = s.account_group_id");
        String unavailable=" s.account_group_id=? AND s.status='ACTIVE' AND NOT EXISTS("+usable+")";
        jdbc.update("""
            INSERT INTO security_audit_event(id,user_id,account_id,session_id,event_type,occurred_at)
            SELECT UUID_TO_BIN(UUID()),g.user_id,s.login_account_id,s.id,'SESSION_REVOKED',?
            FROM user_session s JOIN account_group g ON g.id=s.account_group_id WHERE
            """+unavailable,time(now),bytes(group),time(now),time(now));
        jdbc.update("UPDATE user_session s SET s.status='REVOKED',s.revoked_at=? WHERE "+unavailable,
                time(now),bytes(group),time(now),time(now));
        jdbc.update("""
            UPDATE session_refresh_token r JOIN user_session s ON s.id=r.session_id
            SET r.revoked_at=? WHERE s.account_group_id=? AND s.status='REVOKED' AND r.revoked_at IS NULL
            """,time(now),bytes(group));
        jdbc.update("""
            UPDATE session_account_grant sg JOIN user_session s ON s.id=sg.session_id
            SET sg.status='REVOKED',sg.revoked_at=?,sg.revocation_reason='NO_USABLE_ACCOUNT'
            WHERE s.account_group_id=? AND s.status='REVOKED' AND sg.status='ACTIVE'
            """,time(now),bytes(group));
    }

    public void auditLogoutAll(UUID userId, UUID accountId, UUID sessionId, UUID accountGroupId, Instant now) {
        loginAudits.recordLogoutAll(userId, accountId, sessionId, accountGroupId, now);
    }

    public void audit(Identity identity, UUID sessionId, String event, Instant now) {
        audit(identity == null ? null : identity.userId(), identity == null ? null : identity.accountId(), sessionId, event, now);
    }

    public void audit(UUID userId, UUID accountId, UUID sessionId, String event, Instant now) {
        if ("PASSWORD_RESET_COMPLETED".equals(event)) {
            loginAudits.recordPasswordReset(userId, accountId, now);
            return;
        }
        if ("REFRESH_FAILED".equals(event)) {
            loginAudits.recordRefreshFailure(now);
            return;
        }
        if ("REFRESH_REPLAY".equals(event)) {
            loginAudits.recordRefreshReplay(userId, accountId, sessionId, now);
            return;
        }
        if ("LOGIN_SUCCEEDED".equals(event) || "LOGIN_FAILED".equals(event)) {
            loginAudits.record(userId, accountId, sessionId,
                    com.unidocs.auth.audit.domain.SecurityAuditEvent.Type.valueOf(event), now);
            return;
        }
        jdbc.update("INSERT INTO security_audit_event (id, user_id, account_id, session_id, event_type, occurred_at) VALUES (?, ?, ?, ?, ?, ?)",
                bytes(UUID.randomUUID()), bytes(userId), bytes(accountId), bytes(sessionId), event, time(now));
    }

    public List<Account> accounts(UserSession session, UUID after, int limit, Instant now) {
        return jdbc.query("""
            SELECT a.id, a.display_name, a.type, EXISTS (
                SELECT 1 FROM session_account_grant sg
                JOIN session_grant_policy p ON p.scope_type = 'GLOBAL'
                LEFT JOIN login_identity li ON sg.credential_source = 'LOGIN_IDENTITY' AND li.id = sg.credential_id AND li.account_id = a.id
                LEFT JOIN account_credential ac ON sg.credential_source = 'ACCOUNT_CREDENTIAL' AND ac.id = sg.credential_id AND ac.account_id = a.id
                WHERE sg.session_id = ? AND sg.account_id = a.id AND sg.status = 'ACTIVE'
                    AND sg.idle_expires_at > ? AND sg.absolute_expires_at > ?
                    AND sg.policy_version = p.version
                    AND ((li.status = 'ACTIVE' AND li.credential_version = sg.credential_version)
                        OR (ac.status = 'ACTIVE' AND ac.version = sg.credential_version))
                AND %s
            ) AS unlocked
            FROM account_group_member m JOIN user_account a ON a.id = m.account_id
            JOIN account_group g ON g.id = m.account_group_id
            WHERE m.account_group_id = ? AND m.status = 'LINKED' AND a.status = 'ACTIVE' AND a.user_id = g.user_id
            """.formatted(OrganizationAccountScope.GRANT) + " AND " + OrganizationAccountScope.PASSWORD
                + (after == null ? "" : " AND a.id > ?") + " ORDER BY a.id LIMIT ?",
            (rs, row) -> new Account(id(rs, "id"), rs.getString("display_name"), rs.getString("type"), rs.getBoolean("unlocked")),
            after == null
                ? new Object[]{bytes(session.id()), time(now), time(now), bytes(session.accountGroupId()), limit}
                : new Object[]{bytes(session.id()), time(now), time(now), bytes(session.accountGroupId()), bytes(after), limit});
    }

    public static byte[] bytes(UUID id) {
        return id == null ? null : ByteBuffer.allocate(16).putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits()).array();
    }
    private static UUID id(ResultSet rs, String name) throws SQLException {
        byte[] value = rs.getBytes(name);
        if (value == null) return null;
        ByteBuffer buffer = ByteBuffer.wrap(value);
        return new UUID(buffer.getLong(), buffer.getLong());
    }
    private static Timestamp time(Instant value) { return Timestamp.from(value); }
    private static Instant instant(ResultSet rs, String name) throws SQLException {
        Timestamp value = rs.getTimestamp(name);
        return value == null ? null : value.toInstant();
    }
}
