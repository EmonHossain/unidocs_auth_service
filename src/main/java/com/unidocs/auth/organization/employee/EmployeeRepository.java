package com.unidocs.auth.organization.employee;
import java.time.Instant;
import java.util.UUID;
import java.util.Optional;
import jakarta.persistence.EntityManager;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import com.unidocs.auth.user.domain.*;
import com.unidocs.auth.account.domain.*;
import com.unidocs.auth.authentication.domain.LoginIdentity;
import com.unidocs.auth.session.persistence.SessionRepository;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
@Repository
public class EmployeeRepository {
    public record Credential(UUID accountId, UUID organizationId, UUID groupId, String username, String hash, long version, boolean pending, int attempts) {
        @Override public String toString() { return "EmployeeCredential[REDACTED]"; }
    }
    private final JdbcTemplate jdbc;
    private final EntityManager entities;
    public EmployeeRepository(JdbcTemplate jdbc, EntityManager entities) { this.jdbc=jdbc;this.entities=entities; }
    public EmployeeRequests.Credentials create(UUID org,String type,String name,String username,String hash,UUID actor,UUID request,Instant now,String temporary) {
        User user=new User(UUID.randomUUID(),name,now);
        UserAccount account=new UserAccount(UUID.randomUUID(),user.id(),org,UserAccount.Type.valueOf(type),name,now);
        AccountGroup group=new AccountGroup(UUID.randomUUID(),user.id(),now);
        entities.persist(user); entities.flush(); entities.persist(account); entities.flush();
        entities.persist(new UserProfile(user.id(),now)); entities.persist(new UserPreference(user.id(),account.id(),now));
        entities.persist(group); entities.flush();
        entities.persist(new AccountGroupMember(group,account,now));
        entities.persist(new LoginIdentity(UUID.randomUUID(),account.id(),LoginIdentity.Type.ACCOUNT_ID,account.id().toString(),hash,now));entities.flush();
        jdbc.update("UPDATE login_identity SET status='DISABLED' WHERE account_id=?",bytes(account.id()));
        UUID membership=UUID.randomUUID();
        jdbc.update("INSERT INTO organization_membership(id,organization_id,account_id,role,status,official_email,version,joined_at,created_at,updated_at) VALUES(?,?,?,'MEMBER','ACTIVE',NULL,1,?,?,?)",
                bytes(membership),bytes(org),bytes(account.id()),java.sql.Timestamp.from(now),java.sql.Timestamp.from(now),java.sql.Timestamp.from(now));
        jdbc.update("INSERT INTO employee_activation(account_id,organization_id,username,status,attempts,created_by,request_id,created_at) VALUES(?,?,?,'PENDING',0,?,?,?)",
                bytes(account.id()),bytes(org),username,bytes(actor),bytes(request),java.sql.Timestamp.from(now));
        return new EmployeeRequests.Credentials(account.id(),membership,username,temporary,true);
    }
    public Optional<Credential> credential(String username,boolean lock) {
        return jdbc.query("""
            SELECT e.*,i.password_hash,i.credential_version,g.account_group_id FROM employee_activation e
            JOIN login_identity i ON i.account_id=e.account_id AND i.type='ACCOUNT_ID'
            JOIN account_group_member g ON g.account_id=e.account_id
            WHERE e.username=?
            """+(lock?" FOR UPDATE":""),(rs,n)->new Credential(uuid(rs.getBytes("account_id")),uuid(rs.getBytes("organization_id")),
                    uuid(rs.getBytes("account_group_id")),rs.getString("username"),rs.getString("password_hash"),rs.getLong("credential_version"),"PENDING".equals(rs.getString("status")),rs.getInt("attempts")),username).stream().findFirst();
    }
    public UUID user(UUID account) { return jdbc.queryForObject("SELECT user_id FROM user_account WHERE id=?",(rs,n)->uuid(rs.getBytes(1)),bytes(account)); }
    public boolean currentMember(Credential c) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
            SELECT EXISTS(SELECT 1 FROM user_account a JOIN users u ON u.id=a.user_id JOIN organization_membership m ON m.account_id=a.id
             JOIN organization o ON o.id=m.organization_id JOIN organization_auth_policy p ON p.organization_id=o.id
             JOIN account_group_member g ON g.account_id=a.id
             WHERE a.id=? AND a.status='ACTIVE' AND u.status='ACTIVE' AND o.status='ACTIVE' AND m.status='ACTIVE' AND g.status='LINKED'
               AND p.enabled=true AND p.require_mfa=false AND p.email_domain IS NULL AND p.auth_method='PASSWORD'
               AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=o.id AND r.user_id=u.id AND r.status IN('REMOVED','BLACKLISTED')))
            """,Boolean.class,bytes(c.accountId())));
    }
    public void failed(Credential c) { jdbc.update("UPDATE employee_activation SET attempts=LEAST(attempts+1,5) WHERE account_id=?",bytes(c.accountId())); }
    public void activate(Credential c,String hash,Instant now) {
        jdbc.update("UPDATE login_identity SET password_hash=?,status='ACTIVE',credential_version=credential_version+1,updated_at=? WHERE account_id=? AND type='ACCOUNT_ID'",hash,java.sql.Timestamp.from(now),bytes(c.accountId()));
        jdbc.update("UPDATE employee_activation SET status='ACTIVATED',attempts=0 WHERE account_id=?",bytes(c.accountId()));
    }
    public void reset(UUID account,String hash,Instant now) {
        jdbc.update("UPDATE login_identity SET password_hash=?,status='DISABLED',credential_version=credential_version+1,updated_at=? WHERE account_id=? AND type='ACCOUNT_ID'",hash,java.sql.Timestamp.from(now),bytes(account));
        jdbc.update("UPDATE employee_activation SET status='PENDING',attempts=0 WHERE account_id=?",bytes(account));
        jdbc.update("UPDATE session_account_grant SET status='REVOKED',revoked_at=?,revocation_reason='CREDENTIAL_CHANGED' WHERE account_id=? AND status='ACTIVE'",java.sql.Timestamp.from(now),bytes(account));
    }
    private static UUID uuid(byte[] value) { java.nio.ByteBuffer b=java.nio.ByteBuffer.wrap(value);return new UUID(b.getLong(),b.getLong()); }
    public String type(UUID org) { return jdbc.queryForObject("SELECT type FROM organization WHERE id=?",String.class,bytes(org)); }
    public void lockOrg(UUID org) { jdbc.queryForObject("SELECT id FROM organization WHERE id=? FOR UPDATE",byte[].class,bytes(org)); }
    public long version(UUID org) { return jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(org)); }
    public long changed(UUID org,Instant now) { jdbc.update("UPDATE organization SET authorization_version=authorization_version+1,updated_at=? WHERE id=?",java.sql.Timestamp.from(now),bytes(org));return jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(org)); }
    public Optional<String> username(UUID org,UUID account) { return jdbc.query("SELECT username FROM employee_activation WHERE organization_id=? AND account_id=?",(rs,n)->rs.getString(1),bytes(org),bytes(account)).stream().findFirst(); }
    public UUID membership(UUID org,UUID account) { return jdbc.queryForObject("SELECT id FROM organization_membership WHERE organization_id=? AND account_id=?",(rs,n)->uuid(rs.getBytes(1)),bytes(org),bytes(account)); }
}
