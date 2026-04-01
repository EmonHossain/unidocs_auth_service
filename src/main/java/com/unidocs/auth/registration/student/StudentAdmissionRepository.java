package com.unidocs.auth.registration.student;
import java.util.*;
import java.time.Instant;
import java.nio.ByteBuffer;
import jakarta.persistence.EntityManager;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import com.unidocs.auth.account.domain.*;
import com.unidocs.auth.authentication.domain.LoginIdentity;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.session.application.SessionAccess;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import java.sql.Timestamp;
@Repository
public class StudentAdmissionRepository {
    public void lockStudentPolicy() { jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE",Long.class); }
    public record Admission(UUID id,UUID org,UUID applicant,UUID user,UUID group,String email,String method,String status,String passwordHash,
            String codeHash,Instant expiresAt,int attempts,long version,String evidenceKey,String evidenceType,UUID studentAccount,UUID membership) {
        public StudentRequests.View view() { return new StudentRequests.View(id,org,status,method,expiresAt,studentAccount,membership); }
        @Override public String toString() { return "Admission[REDACTED]"; }
    }
    private final JdbcTemplate jdbc;
    private final EntityManager entities;
    public StudentAdmissionRepository(JdbcTemplate jdbc,EntityManager entities) { this.jdbc=jdbc;this.entities=entities; }
    public void lockUniversity(UUID org) {
        if(jdbc.query("SELECT id FROM organization WHERE id=? AND type='UNIVERSITY' AND status='ACTIVE' FOR UPDATE",(rs,n)->rs.getBytes(1),bytes(org)).isEmpty())throw StudentAdmissionService.denied();
    }
    public boolean instituteEmail(UUID org,String email) {
        String domain=email.substring(email.lastIndexOf('@')+1);
        return !jdbc.query("SELECT domain FROM institute_email_domain WHERE organization_id=? AND domain=?",(rs,n)->rs.getString(1),bytes(org),domain).isEmpty();
    }
    public boolean curator(UUID org,UUID membership) {
        return !jdbc.query("SELECT membership_id FROM institute_curator WHERE organization_id=? AND membership_id=?",(rs,n)->rs.getBytes(1),bytes(org),bytes(membership)).isEmpty();
    }
    public void domain(UUID org,String domain) { jdbc.update("INSERT IGNORE INTO institute_email_domain(organization_id,domain) VALUES(?,?)",bytes(org),domain); }
    public void curator(UUID org,UUID membership,boolean enabled) {
        if(jdbc.query("SELECT id FROM organization_membership WHERE organization_id=? AND id=? AND status='ACTIVE' FOR UPDATE",(rs,n)->rs.getBytes(1),bytes(org),bytes(membership)).isEmpty())throw StudentAdmissionService.denied();
        if(enabled)jdbc.update("INSERT IGNORE INTO institute_curator(organization_id,membership_id) VALUES(?,?)",bytes(org),bytes(membership));
        else jdbc.update("DELETE FROM institute_curator WHERE organization_id=? AND membership_id=?",bytes(org),bytes(membership));
    }
    public void create(UUID id,UUID org,SessionAccess.Context actor,UUID account,String email,String method,String password,String code,Instant expires,String key,String type) {
        jdbc.update("""
            INSERT INTO student_admission(id,organization_id,applicant_account_id,applicant_user_id,account_group_id,email,method,status,
              password_hash,code_hash,code_expires_at,attempts,version,evidence_key,evidence_type,created_at)
            VALUES(?,?,?,?,?,?,?,'EMAIL_PENDING',?,?,?,0,1,?,?,?)
            """,bytes(id),bytes(org),bytes(account),bytes(actor.owner().userId()),bytes(actor.session().accountGroupId()),email,method,password,code,time(expires),key,type,time(actor.now()));
    }
    public Optional<Admission> find(UUID id,boolean lock) {
        return jdbc.query("SELECT * FROM student_admission WHERE id=?"+(lock?" FOR UPDATE":""),(rs,n)->new Admission(uuid(rs.getBytes("id")),uuid(rs.getBytes("organization_id")),
                uuid(rs.getBytes("applicant_account_id")),uuid(rs.getBytes("applicant_user_id")),uuid(rs.getBytes("account_group_id")),rs.getString("email"),rs.getString("method"),rs.getString("status"),
                rs.getString("password_hash"),rs.getString("code_hash"),rs.getTimestamp("code_expires_at").toInstant(),rs.getInt("attempts"),rs.getLong("version"),rs.getString("evidence_key"),rs.getString("evidence_type"),uuid(rs.getBytes("student_account_id")),uuid(rs.getBytes("membership_id"))),bytes(id)).stream().findFirst();
    }
    public List<StudentRequests.View> views(UUID org,UUID after,int limit) {
        String sql="SELECT id,organization_id,status,method,code_expires_at,student_account_id,membership_id FROM student_admission WHERE organization_id=? AND status='PENDING_REVIEW'";
        List<Object> args=new ArrayList<>();args.add(bytes(org));if(after!=null) { sql+=" AND id>?";args.add(bytes(after)); }args.add(limit);
        return jdbc.query(sql+" ORDER BY id LIMIT ?",(rs,n)->new StudentRequests.View(uuid(rs.getBytes("id")),uuid(rs.getBytes("organization_id")),rs.getString("status"),rs.getString("method"),rs.getTimestamp("code_expires_at").toInstant(),uuid(rs.getBytes("student_account_id")),uuid(rs.getBytes("membership_id"))),args.toArray());
    }
    public List<UUID> list(UUID org,UUID after,int limit) {
        return after==null?jdbc.query("SELECT id FROM student_admission WHERE organization_id=? AND status='PENDING_REVIEW' ORDER BY id LIMIT ?",(rs,n)->uuid(rs.getBytes(1)),bytes(org),limit):
                jdbc.query("SELECT id FROM student_admission WHERE organization_id=? AND status='PENDING_REVIEW' AND id>? ORDER BY id LIMIT ?",(rs,n)->uuid(rs.getBytes(1)),bytes(org),bytes(after),limit);
    }
    public void transition(UUID id,String status) { jdbc.update("UPDATE student_admission SET status=?,version=version+1 WHERE id=?",status,bytes(id));if("REJECTED".equals(status))queueEvidence(id); }
    public void failed(Admission a,Instant now) {
        String status=!now.isBefore(a.expiresAt())?"EXPIRED":a.attempts()+1>=5?"FAILED":"EMAIL_PENDING";
        jdbc.update("UPDATE student_admission SET status=?,attempts=LEAST(attempts+1,5),version=version+1 WHERE id=?",status,bytes(a.id()));
        if("EXPIRED".equals(status)||"FAILED".equals(status))queueEvidence(a.id());
    }
    public UUID approve(Admission a,UUID actor,Instant now) {
        if(hasMembership(a.org(),a.user()))throw new com.unidocs.auth.organization.application.OrganizationFailure(org.springframework.http.HttpStatus.CONFLICT);
        String name=jdbc.queryForObject("SELECT display_name FROM users WHERE id=?",String.class,bytes(a.user()));
        UserAccount account=new UserAccount(UUID.randomUUID(),a.user(),a.org(),UserAccount.Type.UNIVERSITY,name,now);
        UUID membership=UUID.randomUUID();entities.persist(account);entities.flush();
        entities.persist(new LoginIdentity(UUID.randomUUID(),account.id(),LoginIdentity.Type.ACCOUNT_ID,account.id().toString(),a.passwordHash(),now));
        entities.persist(new AccountGroupMember(account,a.group(),a.user(),a.applicant(),now));entities.flush();
        entities.persist(new OrganizationMembership(membership,a.org(),account.id(),a.email(),OrganizationMembership.Role.MEMBER,now));entities.flush();
        jdbc.update("UPDATE student_admission SET status='APPROVED',student_account_id=?,membership_id=?,reviewed_by=?,version=version+1 WHERE id=?",bytes(account.id()),bytes(membership),bytes(actor),bytes(a.id()));
        jdbc.update("INSERT INTO iam_student_state(organization_id,membership_id,account_id) VALUES(?,?,?)",bytes(a.org()),bytes(membership),bytes(account.id()));
        queueEvidence(a.id());
        return account.id();
    }
    private void queueEvidence(UUID id) {
        jdbc.update("INSERT IGNORE INTO admission_evidence_deletion(object_key,available_at) SELECT evidence_key,UTC_TIMESTAMP(6) FROM student_admission WHERE id=? AND evidence_key IS NOT NULL",bytes(id));
        jdbc.update("UPDATE student_admission SET password_hash='CONSUMED',code_hash='CONSUMED' WHERE id=?",bytes(id));
    }
    public void review(Admission a,UUID actor,String reason) { jdbc.update("UPDATE student_admission SET reviewed_by=?,review_reason=? WHERE id=?",bytes(actor),reason,bytes(a.id())); }
    public boolean hasMembership(UUID org,UUID user) {
        return !jdbc.query("SELECT m.id FROM organization_membership m JOIN user_account a ON a.id=m.account_id WHERE m.organization_id=? AND a.user_id=? AND m.status<>'PURGED'",(rs,n)->rs.getBytes(1),bytes(org),bytes(user)).isEmpty();
    }
    public boolean applicantCurrent(Admission a) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM user_account a JOIN users u ON u.id=a.user_id JOIN account_group_member m ON m.account_id=a.id JOIN account_group g ON g.id=m.account_group_id WHERE a.id=? AND a.user_id=? AND a.status='ACTIVE' AND u.status='ACTIVE' AND m.status='LINKED' AND g.status='ACTIVE' AND g.id=? AND g.user_id=u.id)",Boolean.class,bytes(a.applicant()),bytes(a.user()),bytes(a.group())));
    }
    public long changed(UUID org,Instant now) { jdbc.update("UPDATE organization SET authorization_version=authorization_version+1,updated_at=? WHERE id=?",time(now),bytes(org));return version(org); }
    public long version(UUID org) { return jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(org)); }
    private static Timestamp time(Instant now) { return Timestamp.from(now); }
    private static UUID uuid(byte[] value) { if(value==null)return null;ByteBuffer b=ByteBuffer.wrap(value);return new UUID(b.getLong(),b.getLong()); }
}
