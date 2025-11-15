package com.unidocs.auth.account.persistence;

import java.nio.ByteBuffer;
import java.sql.*;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import com.unidocs.auth.account.domain.AccountChallenge.*;
import com.unidocs.auth.account.domain.AccountChallenge;
import com.unidocs.auth.organization.persistence.OrganizationAccountScope;
import com.unidocs.auth.session.application.SessionAccess.Context;
import com.unidocs.auth.session.domain.SessionGrantPolicy;

import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Repository
public class AccountAccessRepository {
    private final JdbcTemplate jdbc;
    private final com.unidocs.auth.group.personal.PersonalAccountDeparture personalDeparture;
    public AccountAccessRepository(JdbcTemplate jdbc, com.unidocs.auth.group.personal.PersonalAccountDeparture personalDeparture) {
        this.jdbc = jdbc; this.personalDeparture = personalDeparture;
    }
    public record Target(UUID id, UUID userId, UUID groupId, String linkStatus, String accountStatus,
            boolean organizationAvailable, boolean pinAllowed) { }
    public record Proof(UUID id, UUID accountId, String source, long version, String hash, String status, int failures, Instant lockedUntil) {
        public boolean usableAt(Instant now) {
            if ("ACCOUNT_CREDENTIAL".equals(source)) {
                return new com.unidocs.auth.credential.domain.AccountCredential(id, accountId, hash, status, version, failures, lockedUntil).usableAt(now);
            }
            return "ACTIVE".equals(status);
        }
        @Override public String toString() { return "Proof[REDACTED]"; }
    }

    public Optional<Target> target(UUID accountId) {
        return jdbc.query("""
            SELECT a.id, a.user_id, a.status, m.account_group_id, m.status AS link_status,
                %s AS organization_available, %s AS pin_allowed
            FROM user_account a LEFT JOIN account_group_member m ON m.account_id = a.id WHERE a.id = ? FOR UPDATE
            """.formatted(OrganizationAccountScope.PASSWORD,OrganizationAccountScope.PIN), (rs, row) -> new Target(id(rs,"id"), id(rs,"user_id"), id(rs,"account_group_id"), rs.getString("link_status"), rs.getString("status"),
                    rs.getBoolean("organization_available"),rs.getBoolean("pin_allowed")),
                bytes(accountId)).stream().findFirst();
    }

    public Optional<Proof> proof(UUID accountId, Method method, boolean lock) {
        String sql = method == Method.PASSWORD
            ? "SELECT id, account_id, credential_version AS version, password_hash AS hash, status, 0 AS failures, NULL AS locked_until FROM login_identity WHERE type IN ('EMAIL','ACCOUNT_ID') AND account_id = ?"
            : "SELECT id, account_id, version, credential_hash AS hash, status, failed_attempts AS failures, locked_until FROM account_credential WHERE type = 'PIN' AND account_id = ?";
        return jdbc.query(sql + (lock ? " FOR UPDATE" : ""), (rs, row) -> new Proof(id(rs,"id"), id(rs,"account_id"),
                method == Method.PASSWORD ? "LOGIN_IDENTITY" : "ACCOUNT_CREDENTIAL", rs.getLong("version"),
                rs.getString("hash"), rs.getString("status"), rs.getInt("failures"), instant(rs,"locked_until")), bytes(accountId)).stream().findFirst();
    }

    public AccountChallenge createChallenge(Context actor, Target target, Purpose purpose, Method method, Proof proof, SessionGrantPolicy policy) {
        Instant expiry = actor.now().plus(AccountChallenge.LIFETIME);
        if (actor.session().expiresAt().isBefore(expiry)) expiry = actor.session().expiresAt();
        AccountChallenge challenge = new AccountChallenge(UUID.randomUUID(), actor.session().id(), target.id(), purpose, method, proof.source(),
                proof.id(), proof.version(), policy.version(), "PENDING", 0, expiry);
        jdbc.update("""
            INSERT INTO account_challenge (id, session_id, account_id, purpose, method, credential_source, credential_id,
                credential_version, policy_version, status, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
            """, bytes(challenge.id()), bytes(challenge.sessionId()), bytes(target.id()), purpose.name(), method.name(),
                proof.source(), bytes(proof.id()), proof.version(), policy.version(), time(actor.now()), time(expiry));
        return challenge;
    }

    public Optional<AccountChallenge> challenge(UUID id, boolean lock) {
        return jdbc.query("SELECT * FROM account_challenge WHERE id = ?" + (lock ? " FOR UPDATE" : ""), (rs, row) ->
            new AccountChallenge(id(rs,"id"), id(rs,"session_id"), id(rs,"account_id"), Purpose.valueOf(rs.getString("purpose")),
                Method.valueOf(rs.getString("method")), rs.getString("credential_source"), id(rs,"credential_id"), rs.getLong("credential_version"),
                rs.getLong("policy_version"), rs.getString("status"), rs.getInt("attempts"), instant(rs,"expires_at")), bytes(id)).stream().findFirst();
    }

    public void failure(AccountChallenge challenge, Proof proof, Instant now) {
        int attempts = challenge.attempts() + 1;
        jdbc.update("UPDATE account_challenge SET attempts = ?, status = ? WHERE id = ?", attempts,
                attempts >= 5 ? "FAILED" : "PENDING", bytes(challenge.id()));
        if (challenge.method() == Method.PIN) {
            int failures = proof.lockedUntil() != null && !now.isBefore(proof.lockedUntil()) ? 1 : Math.min(5, proof.failures() + 1);
            jdbc.update("UPDATE account_credential SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?",
                    failures, failures >= 5 ? time(now.plus(java.time.Duration.ofMinutes(15))) : null, time(now), bytes(proof.id()));
        }
    }

    public void consume(AccountChallenge challenge, Instant now) {
        jdbc.update("UPDATE account_challenge SET status = 'CONSUMED', consumed_at = ? WHERE id = ?", time(now), bytes(challenge.id()));
        if (challenge.method() == Method.PIN) jdbc.update("UPDATE account_credential SET failed_attempts = 0, locked_until = NULL WHERE id = ?", bytes(challenge.credentialId()));
    }

    public void expire(AccountChallenge challenge) {
        jdbc.update("UPDATE account_challenge SET status = 'EXPIRED' WHERE id = ? AND status = 'PENDING'", bytes(challenge.id()));
    }

    public void grant(Context actor, Proof proof, Method method, SessionGrantPolicy policy) {
        Instant absolute = policy.absoluteExpiry(actor.now(), actor.session());
        jdbc.update("""
            INSERT INTO session_account_grant (id, session_id, account_id, status, auth_method, credential_version,
                credential_source, credential_id, policy_version, authenticated_at, last_activity_at, idle_expires_at, absolute_expires_at)
            VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE status = 'ACTIVE', auth_method = VALUES(auth_method), credential_version = VALUES(credential_version),
                credential_source = VALUES(credential_source), credential_id = VALUES(credential_id), policy_version = VALUES(policy_version),
                authenticated_at = VALUES(authenticated_at), last_activity_at = VALUES(last_activity_at),
                idle_expires_at = VALUES(idle_expires_at), absolute_expires_at = VALUES(absolute_expires_at), revoked_at = NULL, revocation_reason = NULL
            """, bytes(UUID.randomUUID()), bytes(actor.session().id()), bytes(proof.accountId()), method.name(), proof.version(), proof.source(),
                bytes(proof.id()), policy.version(), time(actor.now()), time(actor.now()), time(policy.idleExpiry(actor.now(), absolute)), time(absolute));
    }

    public void setPin(UUID accountId, String hash, Instant now) {
        jdbc.update("""
            INSERT INTO account_credential (id, account_id, type, credential_hash, status, version, created_at, updated_at)
            VALUES (?, ?, 'PIN', ?, 'ACTIVE', 1, ?, ?)
            ON DUPLICATE KEY UPDATE credential_hash = VALUES(credential_hash), status = 'ACTIVE', version = version + 1,
                failed_attempts = 0, locked_until = NULL, updated_at = VALUES(updated_at)
            """, bytes(UUID.randomUUID()), bytes(accountId), hash, time(now), time(now));
        revokeGrants(accountId, now, "CREDENTIAL_CHANGED", true);
    }

    public void link(Context actor, Target target, Method method) {
        jdbc.update("""
            INSERT INTO account_group_member (account_id, account_group_id, status, link_method, linked_by_account_id, linked_at)
            VALUES (?, ?, 'LINKED', ?, ?, ?)
            ON DUPLICATE KEY UPDATE account_group_id = VALUES(account_group_id), status = 'LINKED', link_method = VALUES(link_method),
                linked_by_account_id = VALUES(linked_by_account_id), linked_at = VALUES(linked_at), disconnected_at = NULL
            """, bytes(target.id()), bytes(actor.session().accountGroupId()), method.name(), bytes(actor.grant().accountId()), time(actor.now()));
    }

    public void unlink(Context actor, Target target) {
        personalDeparture.depart(target.id(), actor.now(), actor.grant().accountId(), actor.owner().userId(), actor.session().id());
        jdbc.update("UPDATE account_group_member SET status = 'DISCONNECTED', disconnected_at = ? WHERE account_id = ?", time(actor.now()), bytes(target.id()));
        revokeGrants(target.id(), actor.now(), "ACCOUNT_UNLINKED", false);
        jdbc.update("UPDATE account_challenge SET status = 'FAILED' WHERE account_id = ? AND status = 'PENDING'", bytes(target.id()));
        if (target.id().equals(actor.owner().preferredAccountId())) {
            List<Fallback> fallback = jdbc.query("""
                SELECT a.id, a.type FROM account_group_member m JOIN user_account a ON a.id = m.account_id
                WHERE m.account_group_id = ? AND m.status = 'LINKED' AND a.status = 'ACTIVE' AND a.user_id = ? AND %s
                ORDER BY (a.type='PERSONAL') DESC, a.created_at, a.id LIMIT 2
                """.formatted(OrganizationAccountScope.PASSWORD), (rs, row) -> new Fallback(id(rs,"id"),rs.getString("type")),
                    bytes(actor.session().accountGroupId()),bytes(actor.owner().userId()));
            UUID preferred = !fallback.isEmpty() && ("PERSONAL".equals(fallback.getFirst().type()) || fallback.size()==1)
                    ? fallback.getFirst().id() : null;
            preferred(actor, preferred);
        }
    }
    private record Fallback(UUID id, String type) { }

    private void revokeGrants(UUID accountId, Instant now, String reason, boolean pinsOnly) {
        jdbc.update("UPDATE session_account_grant SET status = 'REVOKED', revoked_at = ?, revocation_reason = ? WHERE account_id = ? AND status = 'ACTIVE'"
                + (pinsOnly ? " AND credential_source = 'ACCOUNT_CREDENTIAL'" : ""), time(now), reason, bytes(accountId));
    }

    public void preferred(Context actor, UUID accountId) {
        jdbc.update("UPDATE user_preference SET preferred_account_id = ?, updated_at = ? WHERE user_id = ?", bytes(accountId), time(actor.now()), bytes(actor.owner().userId()));
    }

    private static UUID id(ResultSet rs, String column) throws SQLException {
        byte[] bytes = rs.getBytes(column); if (bytes == null) return null;
        ByteBuffer buffer = java.nio.ByteBuffer.wrap(bytes); return new UUID(buffer.getLong(), buffer.getLong());
    }
    private static Instant instant(ResultSet rs, String column) throws SQLException {
        Timestamp timestamp = rs.getTimestamp(column); return timestamp == null ? null : timestamp.toInstant();
    }
    private static Timestamp time(Instant value) { return Timestamp.from(value); }
}
