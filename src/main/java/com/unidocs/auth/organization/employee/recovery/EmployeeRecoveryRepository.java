package com.unidocs.auth.organization.employee.recovery;
import java.util.*;
import java.time.Instant;
import java.sql.Timestamp;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import com.unidocs.auth.organization.employee.EmployeeRepository;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
@Repository
public class EmployeeRecoveryRepository {
    public record Recovery(UUID id,UUID accountId,UUID organizationId,UUID groupId,String username,String status,String hash,long version,int attempts) {
        @Override public String toString() { return "EmployeeRecovery[REDACTED]"; }
    }
    private final JdbcTemplate jdbc;
    public EmployeeRecoveryRepository(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    public Optional<EmployeeRepository.Credential> legacyCredential(String username) {
        UUID account;
        try { account=UUID.fromString(username);if(!account.toString().equals(username))return Optional.empty(); }
        catch(IllegalArgumentException invalid) { return Optional.empty(); }
        return jdbc.query("""
            SELECT a.id,a.organization_id,i.password_hash,i.credential_version,g.account_group_id
            FROM user_account a JOIN users u ON u.id=a.user_id
            JOIN login_identity i ON i.account_id=a.id AND i.type='ACCOUNT_ID' AND i.identifier=?
            JOIN account_group_member g ON g.account_id=a.id AND g.status='LINKED'
            JOIN account_group parent ON parent.id=g.account_group_id AND parent.status='ACTIVE'
            JOIN organization o ON o.id=a.organization_id
            JOIN organization_membership m ON m.account_id=a.id AND m.organization_id=o.id
            WHERE a.id=? AND a.type IN('COMPANY','CUSTOM') AND o.type IN('COMPANY','CUSTOM')
                AND a.status='ACTIVE' AND u.status='ACTIVE' AND o.status='ACTIVE' AND m.status='ACTIVE' AND i.status='ACTIVE'
            """,(rs,n)->new EmployeeRepository.Credential(uuid(rs.getBytes("id")),uuid(rs.getBytes("organization_id")),uuid(rs.getBytes("account_group_id")),username,
                rs.getString("password_hash"),rs.getLong("credential_version"),false,0),username,bytes(account)).stream().findFirst();
    }
    public void seedLegacy(EmployeeRepository.Credential credential,Instant now) {
        jdbc.update("INSERT IGNORE INTO employee_activation(account_id,organization_id,username,status,attempts,created_by,request_id,created_at) VALUES(?,?,?,'ACTIVATED',0,?,?,?)",
            bytes(credential.accountId()),bytes(credential.organizationId()),credential.username(),bytes(credential.accountId()),bytes(UUID.randomUUID()),Timestamp.from(now));
    }
    public boolean request(UUID account,UUID org,UUID id,Instant now) {
        List<Instant> last=jdbc.query("SELECT requested_at FROM employee_password_recovery WHERE account_id=? FOR UPDATE",(rs,n)->rs.getTimestamp(1).toInstant(),bytes(account));
        if(!last.isEmpty()&&last.getFirst().plusSeconds(600).isAfter(now))return false;
        Integer pending=jdbc.queryForObject("SELECT COUNT(*) FROM employee_password_recovery WHERE account_id=? AND status IN('REQUESTED','PIN_ISSUED','LOCKED')",Integer.class,bytes(account));
        if(pending!=null&&pending>0)return false;
        jdbc.update("DELETE FROM employee_password_recovery WHERE account_id=?",bytes(account));
        jdbc.update("INSERT INTO employee_password_recovery(id,account_id,organization_id,status,requested_at) VALUES(?,?,?,'REQUESTED',?)",bytes(id),bytes(account),bytes(org),Timestamp.from(now));
        jdbc.update("""
            INSERT INTO account_security_notice(id,user_id,account_id,organization_id,code,reason,created_at,available_at)
            SELECT UUID_TO_BIN(UUID()),a.user_id,a.id,?,'EMPLOYEE_PASSWORD_RECOVERY_REQUESTED',
                   'Employee password assistance requested; review the organization recovery inbox and independently verify identity.',?,?
            FROM organization_membership m JOIN user_account a ON a.id=m.account_id JOIN users u ON u.id=a.user_id
            WHERE m.organization_id=? AND m.status='ACTIVE' AND m.role IN('OWNER','ADMIN') AND a.status='ACTIVE' AND u.status='ACTIVE'
              AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=m.organization_id AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED'))
            """,bytes(org),Timestamp.from(now),Timestamp.from(now),bytes(org));
        return true;
    }
    public Optional<Recovery> find(UUID id,boolean lock) {
        return jdbc.query("""
            SELECT r.*,e.username,g.account_group_id FROM employee_password_recovery r
            JOIN employee_activation e ON e.account_id=r.account_id
            JOIN account_group_member g ON g.account_id=r.account_id WHERE r.id=?
            """+(lock?" FOR UPDATE":""),(rs,n)->new Recovery(uuid(rs.getBytes("id")),uuid(rs.getBytes("account_id")),uuid(rs.getBytes("organization_id")),
            uuid(rs.getBytes("account_group_id")),rs.getString("username"),rs.getString("status"),rs.getString("pin_hash"),rs.getLong("credential_version"),rs.getInt("attempts")),bytes(id)).stream().findFirst();
    }
    public List<EmployeeRecoveryRequests.View> list(UUID org,UUID after,int limit) {
        List<Object> args=new ArrayList<>();args.add(bytes(org));if(after!=null)args.add(bytes(after));args.add(limit);
        return jdbc.query("SELECT r.*,e.username FROM employee_password_recovery r JOIN employee_activation e ON e.account_id=r.account_id WHERE r.organization_id=? AND r.status IN('REQUESTED','PIN_ISSUED','LOCKED')"+(after==null?"":" AND r.id>?")+" ORDER BY r.id LIMIT ?",
            (rs,n)->new EmployeeRecoveryRequests.View(uuid(rs.getBytes("id")),uuid(rs.getBytes("account_id")),rs.getString("username"),rs.getString("status"),rs.getTimestamp("requested_at").toInstant(),rs.getInt("attempts")),args.toArray());
    }
    public String role(UUID organization,UUID account) {
        return jdbc.queryForObject("SELECT role FROM organization_membership WHERE organization_id=? AND account_id=? AND status='ACTIVE'",String.class,bytes(organization),bytes(account));
    }
    public void issue(Recovery r,String pinHash,String unusablePasswordHash,Instant now) {
        jdbc.update("UPDATE login_identity SET password_hash=?,status='DISABLED',credential_version=credential_version+1,updated_at=? WHERE account_id=? AND type='ACCOUNT_ID'",unusablePasswordHash,Timestamp.from(now),bytes(r.accountId()));
        Long version=jdbc.queryForObject("SELECT credential_version FROM login_identity WHERE account_id=? AND type='ACCOUNT_ID'",Long.class,bytes(r.accountId()));
        jdbc.update("UPDATE employee_activation SET status='ACTIVATED',attempts=0 WHERE account_id=?",bytes(r.accountId()));
        jdbc.update("UPDATE employee_password_recovery SET status='PIN_ISSUED',pin_hash=?,credential_version=?,attempts=0,issued_at=? WHERE id=?",pinHash,version,Timestamp.from(now),bytes(r.id()));
        jdbc.update("INSERT INTO account_security_notice(id,user_id,account_id,organization_id,code,reason,created_at,available_at) SELECT ?,a.user_id,a.id,?,'EMPLOYEE_RECOVERY_PIN_ISSUED','An administrator reset your employee credentials. Collect your recovery PIN through your trusted organization channel.',?,? FROM user_account a WHERE a.id=?",bytes(UUID.randomUUID()),bytes(r.organizationId()),Timestamp.from(now),Timestamp.from(now),bytes(r.accountId()));
    }
    public void failed(Recovery r) { jdbc.update("UPDATE employee_password_recovery SET status=IF(attempts>=4,'LOCKED',status),attempts=LEAST(attempts+1,5),pin_hash=IF(attempts>=5,NULL,pin_hash) WHERE id=?",bytes(r.id())); }
    public void complete(Recovery r,String hash,Instant now) {
        jdbc.update("UPDATE login_identity SET password_hash=?,status='ACTIVE',credential_version=credential_version+1,updated_at=? WHERE account_id=? AND type='ACCOUNT_ID'",hash,Timestamp.from(now),bytes(r.accountId()));
        jdbc.update("UPDATE employee_password_recovery SET status='COMPLETED',pin_hash=NULL,completed_at=? WHERE id=?",Timestamp.from(now),bytes(r.id()));
    }
    private static UUID uuid(byte[] value) { java.nio.ByteBuffer buffer=java.nio.ByteBuffer.wrap(value);return new UUID(buffer.getLong(),buffer.getLong()); }
}
