package com.unidocs.auth.credential.recovery.email;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import com.unidocs.auth.organization.persistence.OrganizationAccountScope;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Repository
public class EmailRecoveryRepository {
    private final JdbcTemplate jdbc;
    public EmailRecoveryRepository(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    public record Target(UUID identityId,UUID accountId,UUID userId,UUID groupId,UUID organizationId,
            String email,String passwordHash,long credentialVersion) {
        @Override public String toString() { return "Target[REDACTED]"; }
    }
    public record Challenge(UUID id,UUID accountId,UUID identityId,UUID groupId,String email,String hash,
            long version,String status,int attempts,Instant expiresAt) {
        @Override public String toString() { return "Challenge[REDACTED]"; }
    }
    private static final String ELIGIBLE="""
        SELECT i.id AS identity_id,a.id AS account_id,a.user_id,g.id AS group_id,a.organization_id,
            i.password_hash,i.credential_version,
            CASE WHEN a.type='PERSONAL' THEN i.identifier ELSE om.official_email END AS recovery_email
        FROM login_identity i JOIN user_account a ON a.id=i.account_id
        JOIN users u ON u.id=a.user_id
        JOIN account_group_member gm ON gm.account_id=a.id
        JOIN account_group g ON g.id=gm.account_group_id
        LEFT JOIN organization o ON o.id=a.organization_id
        LEFT JOIN organization_membership om ON om.organization_id=o.id AND om.account_id=a.id
        WHERE i.status='ACTIVE' AND a.status='ACTIVE' AND u.status='ACTIVE'
            AND gm.status='LINKED' AND g.status='ACTIVE' AND g.user_id=a.user_id
            AND ((a.type='PERSONAL' AND a.organization_id IS NULL AND i.type='EMAIL'
                AND EXISTS(SELECT 1 FROM user_contact c WHERE c.user_id=a.user_id
                    AND c.type='EMAIL' AND c.value=i.identifier AND c.verified=true))
                OR (a.type='UNIVERSITY' AND o.type='UNIVERSITY' AND i.type='ACCOUNT_ID'
                    AND om.status='ACTIVE' AND om.official_email IS NOT NULL))
        """+" AND "+OrganizationAccountScope.PASSWORD;
    public Optional<Target> target(String email,UUID account,boolean lock) {
        String filter=" AND "+(account==null?"a.type='PERSONAL'":"a.id=?")
                +" AND (CASE WHEN a.type='PERSONAL' THEN i.identifier ELSE om.official_email END)=?";
        Object[] parameters=account==null?new Object[]{email}:new Object[]{bytes(account),email};
        return jdbc.query(ELIGIBLE+filter+(lock?" FOR UPDATE":""),this::target,parameters).stream().findFirst();
    }
    private Target target(ResultSet rs,int row)throws SQLException {
        return new Target(id(rs,"identity_id"),id(rs,"account_id"),id(rs,"user_id"),id(rs,"group_id"),
                id(rs,"organization_id"),rs.getString("recovery_email"),rs.getString("password_hash"),rs.getLong("credential_version"));
    }
    public boolean throttled(UUID identity,Instant now) {
        Integer count=jdbc.queryForObject("SELECT COUNT(*) FROM email_password_recovery WHERE identity_id=? AND created_at>?",
                Integer.class,bytes(identity),time(now.minus(Duration.ofHours(1))));
        Integer recent=jdbc.queryForObject("SELECT COUNT(*) FROM email_password_recovery WHERE identity_id=? AND created_at>?",
                Integer.class,bytes(identity),time(now.minusSeconds(60)));
        return count!=null&&count>=5||recent!=null&&recent>0;
    }
    public void create(UUID id,Target target,String hash,Instant now) {
        jdbc.update("UPDATE email_password_recovery SET status='SUPERSEDED',code_hash='CONSUMED' WHERE identity_id=? AND status='PENDING'",bytes(target.identityId()));
        jdbc.update("""
            INSERT INTO email_password_recovery(id,account_id,identity_id,credential_version,destination,code_hash,status,attempts,created_at,expires_at)
            VALUES(?,?,?,?,?,?,'PENDING',0,?,?)
            """,bytes(id),bytes(target.accountId()),bytes(target.identityId()),target.credentialVersion(),target.email(),hash,time(now),time(now.plusSeconds(300)));
    }
    public Optional<Challenge> challenge(UUID id,boolean lock) {
        return jdbc.query("""
            SELECT r.*,gm.account_group_id FROM email_password_recovery r
            JOIN account_group_member gm ON gm.account_id=r.account_id WHERE r.id=?
            """+(lock?" FOR UPDATE":""),(rs,n)->new Challenge(id(rs,"id"),id(rs,"account_id"),id(rs,"identity_id"),id(rs,"account_group_id"),
                    rs.getString("destination"),rs.getString("code_hash"),rs.getLong("credential_version"),rs.getString("status"),rs.getInt("attempts"),rs.getTimestamp("expires_at").toInstant()),bytes(id)).stream().findFirst();
    }
    public void failed(Challenge challenge,Instant now) {
        if(!now.isBefore(challenge.expiresAt())) {
            jdbc.update("UPDATE email_password_recovery SET status='EXPIRED',code_hash='CONSUMED' WHERE id=?",bytes(challenge.id()));
        } else {
            jdbc.update("UPDATE email_password_recovery SET code_hash=CASE WHEN attempts+1>=5 THEN 'CONSUMED' ELSE code_hash END,status=CASE WHEN attempts+1>=5 THEN 'FAILED' ELSE 'PENDING' END,attempts=attempts+1 WHERE id=? AND attempts<5",bytes(challenge.id()));
        }
    }
    public void complete(Challenge challenge,Target target,String password,Instant now) {
        jdbc.update("UPDATE login_identity SET password_hash=?,credential_version=credential_version+1,updated_at=? WHERE id=?",password,time(now),bytes(target.identityId()));
        jdbc.update("UPDATE email_password_recovery SET status='COMPLETED',code_hash='CONSUMED',completed_at=? WHERE id=?",time(now),bytes(challenge.id()));
        jdbc.update("UPDATE email_password_recovery SET status='SUPERSEDED',code_hash='CONSUMED' WHERE identity_id=? AND status='PENDING'",bytes(target.identityId()));
    }
    private static Timestamp time(Instant now) { return Timestamp.from(now); }
    private static UUID id(ResultSet rs,String column)throws SQLException {
        byte[] value=rs.getBytes(column);if(value==null)return null;
        ByteBuffer b=ByteBuffer.wrap(value);return new UUID(b.getLong(),b.getLong());
    }
}
