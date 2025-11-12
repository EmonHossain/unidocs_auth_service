package com.unidocs.auth.account.lifecycle;

import java.nio.ByteBuffer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import com.unidocs.auth.organization.persistence.OrganizationAccountScope;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Repository
public class LifecycleRepository {
    private final JdbcTemplate jdbc;
    private final com.unidocs.auth.group.personal.PersonalAccountDeparture personalDeparture;
    public LifecycleRepository(JdbcTemplate jdbc, com.unidocs.auth.group.personal.PersonalAccountDeparture personalDeparture) {
        this.jdbc=jdbc; this.personalDeparture=personalDeparture;
    }
    public record Account(UUID id, UUID userId, UUID groupId, UUID organizationId, String type,
            String displayName, String status, long version, Instant retainUntil) { }
    public record Proof(UUID id, UUID accountId, String hash, long version, int attempts, Instant lockedUntil) {
        @Override public String toString() { return "Proof[REDACTED]"; }
    }
    public record Member(UUID id, UUID accountId, UUID userId, UUID groupId, String role) { }
    public record Restriction(UUID id, UUID organizationId, UUID userId, UUID groupId, String status,
            long version, Instant retainUntil, Instant blacklistUntil) { }
    public record Removal(UUID id, UUID accountId, UUID userId, UUID organizationId, String status, Instant createdAt) { }
    public record Notice(UUID id, UUID accountId, UUID organizationId, String code, String reason, Instant deadline, Instant createdAt) { }

    private static final String ACCOUNT="""
        SELECT a.*,g.id group_id FROM user_account a JOIN account_group g ON g.user_id=a.user_id WHERE a.id=?
        """;
    public Optional<Account> account(UUID id, boolean lock) {
        return jdbc.query(ACCOUNT+(lock?" FOR UPDATE":""),this::mapAccount,bytes(id)).stream().findFirst();
    }
    private Account mapAccount(ResultSet rs,int row) throws SQLException {
        return new Account(id(rs,"id"),id(rs,"user_id"),id(rs,"group_id"),id(rs,"organization_id"),rs.getString("type"),
                rs.getString("display_name"),rs.getString("status"),rs.getLong("lifecycle_version"),instant(rs,"retain_until"));
    }
    public List<Account> options(UUID user,UUID after,int limit) {
        return jdbc.query("""
            SELECT a.*,g.id group_id FROM user_account a JOIN account_group g ON g.user_id=a.user_id
            JOIN account_group_member m ON m.account_id=a.id AND m.account_group_id=g.id
            WHERE a.user_id=? AND m.status='LINKED' AND a.status<>'PURGED'
            """+(after==null?"":" AND a.id>?")+" ORDER BY a.id LIMIT ?",this::mapAccount,
                after==null?new Object[]{bytes(user),limit}:new Object[]{bytes(user),bytes(after),limit});
    }
    public boolean linked(Account account) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM account_group_member WHERE account_id=? AND account_group_id=? AND status='LINKED'",
                Integer.class,bytes(account.id()),bytes(account.groupId()))==1;
    }
    public Optional<Proof> proof(UUID account,boolean lock) {
        return jdbc.query("SELECT * FROM login_identity WHERE account_id=? AND status='ACTIVE'"+(lock?" FOR UPDATE":""),
                (rs,n)->new Proof(id(rs,"id"),account,rs.getString("password_hash"),rs.getLong("credential_version"),
                        rs.getInt("lifecycle_attempts"),instant(rs,"lifecycle_locked_until")),bytes(account)).stream().findFirst();
    }
    public boolean verify(Proof candidate,boolean matched,Instant now) {
        if(candidate==null) return false;
        Proof current=proof(candidate.accountId(),true).orElse(null);
        if(current==null || current.version()!=candidate.version() || !current.id().equals(candidate.id())
                || !current.hash().equals(candidate.hash()) || current.lockedUntil()!=null && now.isBefore(current.lockedUntil())) return false;
        if(matched) {
            jdbc.update("UPDATE login_identity SET lifecycle_attempts=0,lifecycle_locked_until=NULL WHERE id=?",bytes(current.id()));
            return true;
        }
        int attempts=current.lockedUntil()!=null?1:Math.min(5,current.attempts()+1);
        jdbc.update("UPDATE login_identity SET lifecycle_attempts=?,lifecycle_locked_until=? WHERE id=?",attempts,
                attempts==5?time(now.plusSeconds(900)):null,bytes(current.id()));
        return false;
    }
    public boolean employee(UUID user) { return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM employee_activation e JOIN user_account a ON a.id=e.account_id WHERE a.user_id=?)",Boolean.class,bytes(user))); }
    public Optional<String> email(UUID user) {
        return jdbc.query("SELECT value FROM user_contact WHERE user_id=? AND type='EMAIL' AND is_primary=true AND verified=true LIMIT 1",
                (rs,n)->rs.getString(1),bytes(user)).stream().findFirst();
    }
    public void personalRemove(Account account,Instant deadline,Instant now) {
        jdbc.update("UPDATE user_account SET status='SOFT_DELETED',removed_at=?,retain_until=?,lifecycle_version=lifecycle_version+1,updated_at=? WHERE id=?",
                time(now),time(deadline),time(now),bytes(account.id()));
        revokeAccount(account.id(),now);
    }
    public void restorePersonal(Account account,Instant now) {
        jdbc.update("UPDATE user_account SET status='ACTIVE',removed_at=NULL,retain_until=NULL,lifecycle_version=lifecycle_version+1,updated_at=? WHERE id=?",
                time(now),bytes(account.id()));
        credentialsChanged(account.id(),now);
    }
    private void credentialsChanged(UUID account,Instant now) {
        jdbc.update("UPDATE login_identity SET credential_version=credential_version+1,updated_at=? WHERE account_id=?",time(now),bytes(account));
        jdbc.update("UPDATE account_credential SET version=version+1,updated_at=? WHERE account_id=?",time(now),bytes(account));
    }
    public void revokeAccount(UUID account,Instant now) {
        credentialsChanged(account,now);
        jdbc.update("UPDATE session_account_grant SET status='REVOKED',revoked_at=?,revocation_reason='CREDENTIAL_CHANGED' WHERE account_id=? AND status='ACTIVE'",time(now),bytes(account));
        jdbc.update("UPDATE account_challenge SET status='FAILED' WHERE account_id=? AND status='PENDING'",bytes(account));
    }
    public void fallback(UUID user,Instant now) {
        List<UUID> choices=jdbc.query("""
            SELECT a.id FROM user_account a JOIN account_group_member m ON m.account_id=a.id
            JOIN account_group g ON g.id=m.account_group_id
            WHERE a.user_id=? AND g.user_id=a.user_id AND m.status='LINKED' AND a.status='ACTIVE' AND
            """+OrganizationAccountScope.PASSWORD+" ORDER BY (a.type='PERSONAL') DESC,a.created_at,a.id LIMIT 2",
                (rs,n)->id(rs,"id"),bytes(user));
        UUID preferred=choices.isEmpty()?null:choices.getFirst();
        if(choices.size()>1 && !"PERSONAL".equals(account(preferred,false).orElseThrow().type())) preferred=null;
        jdbc.update("UPDATE user_preference SET preferred_account_id=?,updated_at=? WHERE user_id=?",bytes(preferred),time(now),bytes(user));
    }
    public boolean lastOwner(UUID user,UUID organization) {
        return jdbc.queryForObject("""
            SELECT COUNT(*) FROM organization_membership m JOIN user_account a ON a.id=m.account_id
            WHERE a.user_id=? AND m.role='OWNER' AND m.status='ACTIVE' AND a.status='ACTIVE'
            """+(organization==null?"":" AND m.organization_id=?")+"""
            AND NOT EXISTS(SELECT 1 FROM organization_membership other JOIN user_account oa ON oa.id=other.account_id
                WHERE other.organization_id=m.organization_id AND other.role='OWNER' AND other.status='ACTIVE'
                AND oa.status='ACTIVE' AND oa.user_id<>a.user_id
                AND EXISTS(SELECT 1 FROM users owner_user JOIN account_group owner_group ON owner_group.user_id=owner_user.id
                    JOIN account_group_member owner_link ON owner_link.account_group_id=owner_group.id
                    WHERE owner_user.id=oa.user_id AND owner_user.status='ACTIVE' AND owner_group.status='ACTIVE'
                        AND owner_link.account_id=oa.id AND owner_link.status='LINKED'))
            """,Integer.class,organization==null?new Object[]{bytes(user)}:new Object[]{bytes(user),bytes(organization)})>0;
    }
    public boolean ownsOrganization(UUID user,UUID organization) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM organization_membership m JOIN user_account a ON a.id=m.account_id WHERE a.user_id=? AND m.organization_id=? AND m.role='OWNER' AND (m.status='ACTIVE' OR m.status='REVOKED' AND m.restriction_id IS NOT NULL)",Integer.class,bytes(user),bytes(organization))>0;
    }
    public record OrganizationVersion(UUID id,long version) { }
    public List<OrganizationVersion> accountOrganizations(UUID account,UUID after,int limit) {
        return jdbc.query("SELECT o.id,o.authorization_version FROM organization o JOIN organization_membership m ON m.organization_id=o.id WHERE m.account_id=? AND m.status='ACTIVE'"
                +(after==null?"":" AND o.id>?")+" ORDER BY o.id LIMIT ?",(rs,n)->new OrganizationVersion(id(rs,"id"),rs.getLong("authorization_version")),
                after==null?new Object[]{bytes(account),limit}:new Object[]{bytes(account),bytes(after),limit});
    }
    public boolean lastAccountOwner(UUID account) {
        return jdbc.queryForObject("""
            SELECT COUNT(*) FROM organization_membership m JOIN user_account a ON a.id=m.account_id
            WHERE a.id=? AND m.role='OWNER' AND m.status='ACTIVE' AND a.status='ACTIVE'
            AND NOT EXISTS(SELECT 1 FROM organization_membership other JOIN user_account oa ON oa.id=other.account_id
                WHERE other.organization_id=m.organization_id AND other.role='OWNER' AND other.status='ACTIVE'
                AND oa.status='ACTIVE' AND oa.id<>a.id
                AND EXISTS(SELECT 1 FROM users owner_user JOIN account_group owner_group ON owner_group.user_id=owner_user.id
                    JOIN account_group_member owner_link ON owner_link.account_group_id=owner_group.id
                    WHERE owner_user.id=oa.user_id AND owner_user.status='ACTIVE' AND owner_group.status='ACTIVE'
                        AND owner_link.account_id=oa.id AND owner_link.status='LINKED'))
            """,Integer.class,bytes(account))>0;
    }
    public Optional<Account> restrictedAccount(Restriction restriction) {
        return jdbc.query("SELECT a.*,g.id group_id FROM organization_membership m JOIN user_account a ON a.id=m.account_id JOIN account_group g ON g.user_id=a.user_id WHERE m.restriction_id=? AND m.status='REVOKED' AND a.status<>'PURGED' ORDER BY a.id LIMIT 1",
                this::mapAccount,bytes(restriction.id())).stream().findFirst();
    }
    public void lockOrganization(UUID org) {
        if(jdbc.query("SELECT id FROM organization WHERE id=? FOR UPDATE",(rs,n)->id(rs,"id"),bytes(org)).isEmpty())
            throw LifecycleFailure.forbidden();
    }
    public Optional<Member> member(UUID org,UUID membership) {
        return jdbc.query("""
            SELECT m.*,a.user_id,g.id group_id FROM organization_membership m
            JOIN user_account a ON a.id=m.account_id JOIN account_group g ON g.user_id=a.user_id
            WHERE m.organization_id=? AND m.id=? AND m.status<>'PURGED'
            """,(rs,n)->new Member(id(rs,"id"),id(rs,"account_id"),id(rs,"user_id"),id(rs,"group_id"),rs.getString("role")),
                bytes(org),bytes(membership)).stream().findFirst();
    }
    public Optional<Member> memberForAccount(UUID org,UUID account) {
        return jdbc.query("SELECT id FROM organization_membership WHERE organization_id=? AND account_id=? AND status<>'PURGED'",
                (rs,n)->id(rs,"id"),bytes(org),bytes(account)).stream().findFirst().flatMap(id->member(org,id));
    }
    public Optional<Restriction> restriction(UUID org,UUID user,boolean lock) {
        return jdbc.query("""
            SELECT r.*,g.id group_id FROM organization_account_restriction r JOIN account_group g ON g.user_id=r.user_id
            WHERE r.organization_id=? AND r.user_id=?
            """+(lock?" FOR UPDATE":""),this::mapRestriction,bytes(org),bytes(user)).stream().findFirst();
    }
    private Restriction mapRestriction(ResultSet rs,int row) throws SQLException {
        return new Restriction(id(rs,"id"),id(rs,"organization_id"),id(rs,"user_id"),id(rs,"group_id"),rs.getString("status"),
                rs.getLong("version"),instant(rs,"retain_until"),instant(rs,"blacklist_until"));
    }
    public Restriction restrict(UUID org,Member member,UUID actor,String status,Instant deadline,Instant now) {
        Restriction old=restriction(org,member.userId(),true).orElse(null);
        UUID restriction=old==null?UUID.randomUUID():old.id();
        Instant retain="REMOVED".equals(status)?deadline:null;
        Instant blocked="BLACKLISTED".equals(status)?deadline:null;
        jdbc.update("""
            INSERT INTO organization_account_restriction(id,organization_id,user_id,status,version,retain_until,blacklist_until,updated_at)
            VALUES(?,?,?,?,1,?,?,?) ON DUPLICATE KEY UPDATE status=VALUES(status),version=version+1,
            retain_until=VALUES(retain_until),blacklist_until=VALUES(blacklist_until),updated_at=VALUES(updated_at)
            """,bytes(restriction),bytes(org),bytes(member.userId()),status,time(retain),time(blocked),time(now));
        jdbc.update("""
            UPDATE organization_membership m JOIN user_account a ON a.id=m.account_id
            SET m.status='REVOKED',m.revoked_at=?,m.revoked_by=?,m.version=m.version+1,m.restriction_id=?,m.updated_at=?
            WHERE m.organization_id=? AND a.user_id=? AND m.status='ACTIVE'
            """,time(now),bytes(actor),bytes(restriction),time(now),bytes(org),bytes(member.userId()));
        jdbc.update("""
            UPDATE user_account SET status=?,removed_at=?,retain_until=?,blacklist_until=?,restriction_id=?,
                lifecycle_version=lifecycle_version+1,updated_at=?
            WHERE organization_id=? AND user_id=? AND (status='ACTIVE' OR restriction_id=?)
            ""","REMOVED".equals(status)?"SOFT_DELETED":"BLACKLISTED",time(retain==null?null:now),time(retain),time(blocked),
                bytes(restriction),time(now),bytes(org),bytes(member.userId()),bytes(restriction));
        affectedAccounts(org,member.userId()).forEach(account->revokeAccount(account,now));
        return restriction(org,member.userId(),true).orElseThrow();
    }
    public List<UUID> affectedAccounts(UUID org,UUID user) {
        return jdbc.query("SELECT id FROM user_account WHERE organization_id=? AND user_id=? AND status<>'PURGED'",(rs,n)->id(rs,"id"),bytes(org),bytes(user));
    }
    public void restoreRestriction(Restriction restriction,Instant now) {
        jdbc.update("""
            UPDATE organization_membership SET status='ACTIVE',revoked_at=NULL,revoked_by=NULL,restriction_id=NULL,
                version=version+1,updated_at=? WHERE restriction_id=? AND status='REVOKED'
            """,time(now),bytes(restriction.id()));
        jdbc.update("""
            UPDATE user_account SET status='ACTIVE',removed_at=NULL,retain_until=NULL,blacklist_until=NULL,restriction_id=NULL,
                lifecycle_version=lifecycle_version+1,updated_at=? WHERE restriction_id=? AND status IN('SOFT_DELETED','BLACKLISTED')
            """,time(now),bytes(restriction.id()));
        affectedAccounts(restriction.organizationId(),restriction.userId()).forEach(account->credentialsChanged(account,now));
        jdbc.update("UPDATE organization_account_restriction SET status='ACTIVE',retain_until=NULL,blacklist_until=NULL,version=version+1,updated_at=? WHERE id=?",
                time(now),bytes(restriction.id()));
    }
    public long bumpOrganization(UUID org,Instant now) {
        jdbc.update("UPDATE organization SET authorization_version=authorization_version+1,updated_at=? WHERE id=?",time(now),bytes(org));
        return jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(org));
    }
    public Removal request(UUID request,Account account,Instant now) {
        Optional<Removal> old=removal(request,false);
        if(old.isPresent()) {
            if(!old.get().accountId().equals(account.id())) throw LifecycleFailure.conflict("REQUEST_ID_REUSED");
            return old.get();
        }
        if(jdbc.queryForObject("SELECT COUNT(*) FROM account_removal_request WHERE account_id=? AND status='PENDING'",Integer.class,bytes(account.id()))>0)
            throw LifecycleFailure.conflict("REMOVAL_ALREADY_REQUESTED");
        jdbc.update("INSERT INTO account_removal_request(id,account_id,user_id,organization_id,status,created_at) VALUES(?,?,?,?,'PENDING',?)",
                bytes(request),bytes(account.id()),bytes(account.userId()),bytes(account.organizationId()),time(now));
        return removal(request,false).orElseThrow();
    }
    public Optional<Removal> removal(UUID id,boolean lock) {
        return jdbc.query("SELECT * FROM account_removal_request WHERE id=?"+(lock?" FOR UPDATE":""),this::mapRemoval,bytes(id)).stream().findFirst();
    }
    private Removal mapRemoval(ResultSet rs,int n) throws SQLException {
        return new Removal(id(rs,"id"),id(rs,"account_id"),id(rs,"user_id"),id(rs,"organization_id"),rs.getString("status"),instant(rs,"created_at"));
    }
    public List<Removal> removals(UUID org,UUID user,UUID after,int limit) {
        ArrayList<Object> args=new ArrayList<>(); args.add(bytes(org==null?user:org));
        if(after!=null) args.add(bytes(after)); args.add(limit);
        return jdbc.query("SELECT * FROM account_removal_request WHERE "+(org==null?"user_id":"organization_id")+"=?"
                +(after==null?"":" AND id>?")+" ORDER BY id LIMIT ?",this::mapRemoval,args.toArray());
    }
    public void review(Removal request,UUID actor,String status,Instant now) {
        jdbc.update("UPDATE account_removal_request SET status=?,reviewed_at=?,reviewed_by=? WHERE id=? AND status='PENDING'",
                status,time(now),bytes(actor),bytes(request.id()));
    }
    public UUID notice(Account account,String code,String reason,Instant deadline,Instant now) {
        UUID id=UUID.randomUUID();
        jdbc.update("INSERT INTO account_security_notice(id,user_id,account_id,organization_id,code,reason,deadline,created_at,available_at) VALUES(?,?,?,?,?,?,?,?,?)",
                bytes(id),bytes(account.userId()),bytes(account.id()),bytes(account.organizationId()),code,reason,time(deadline),time(now),time(now));
        return id;
    }
    public List<Notice> notices(UUID user,UUID after,int limit) {
        return jdbc.query("SELECT * FROM account_security_notice WHERE user_id=?"+(after==null?"":" AND id>?")+" ORDER BY id LIMIT ?",
                (rs,n)->new Notice(id(rs,"id"),id(rs,"account_id"),id(rs,"organization_id"),rs.getString("code"),rs.getString("reason"),instant(rs,"deadline"),instant(rs,"created_at")),
                after==null?new Object[]{bytes(user),limit}:new Object[]{bytes(user),bytes(after),limit});
    }
    public List<Account> duePersonal(Instant now,int limit) {
        return jdbc.query("SELECT a.*,g.id group_id FROM user_account a JOIN account_group g ON g.user_id=a.user_id WHERE a.organization_id IS NULL AND a.status='SOFT_DELETED' AND a.retain_until<=? ORDER BY a.retain_until,a.id LIMIT ?",
                this::mapAccount,time(now),limit);
    }
    public List<Restriction> dueRestrictions(Instant now,int limit) {
        return jdbc.query("""
            SELECT r.*,g.id group_id FROM organization_account_restriction r JOIN account_group g ON g.user_id=r.user_id
            WHERE (r.status='REMOVED' AND r.retain_until<=?) OR (r.status='BLACKLISTED' AND r.blacklist_until<=?)
            ORDER BY r.updated_at,r.id LIMIT ?
            """,this::mapRestriction,time(now),time(now),limit);
    }
    public void purge(Account account,Instant now) {
        personalDeparture.depart(account.id(), now, null, account.userId(), null);
        revokeAccount(account.id(),now);
        jdbc.update("DELETE FROM group_membership WHERE account_id=?",bytes(account.id()));
        jdbc.update("DELETE FROM group_join_request WHERE account_id=?",bytes(account.id()));
        jdbc.update("DELETE FROM group_invitation WHERE account_id=?",bytes(account.id()));
        jdbc.update("DELETE FROM student_enrollment WHERE account_id=?",bytes(account.id()));
        jdbc.update("DELETE FROM account_challenge WHERE account_id=?",bytes(account.id()));
        jdbc.update("DELETE FROM account_credential WHERE account_id=?",bytes(account.id()));
        jdbc.update("INSERT IGNORE INTO admission_evidence_deletion(object_key,available_at) SELECT evidence_key,? FROM student_admission WHERE (applicant_account_id=? OR student_account_id=?) AND evidence_key IS NOT NULL",time(now),bytes(account.id()),bytes(account.id()));
        jdbc.update("DELETE FROM student_admission WHERE applicant_account_id=? OR student_account_id=?",bytes(account.id()),bytes(account.id()));
        jdbc.update("DELETE FROM email_password_recovery WHERE account_id=?",bytes(account.id()));
        jdbc.update("DELETE FROM employee_password_recovery WHERE account_id=?",bytes(account.id()));
        jdbc.update("DELETE FROM employee_activation WHERE account_id=?",bytes(account.id()));
        jdbc.update("DELETE FROM login_identity WHERE account_id=?",bytes(account.id()));
        jdbc.update("UPDATE session_refresh_token r JOIN user_session s ON s.id=r.session_id SET r.secret_hash=REPEAT('0',64) WHERE s.login_account_id=?",bytes(account.id()));
        jdbc.update("DELETE v FROM registration_verification v JOIN pending_registration p ON p.id=v.pending_registration_id WHERE p.provisioned_account_id=?",bytes(account.id()));
        jdbc.update("DELETE FROM pending_registration WHERE provisioned_account_id=?",bytes(account.id()));
        jdbc.update("DELETE FROM account_security_notice WHERE account_id=?",bytes(account.id()));
        jdbc.update("UPDATE organization_invitation SET official_email='deleted',token_hash=REPEAT('0',64) WHERE accepted_account_id=?",bytes(account.id()));
        jdbc.update("UPDATE organization_membership SET status='PURGED',official_email='deleted',member_code=NULL,external_identity=NULL,revoked_at=COALESCE(revoked_at,?),revoked_by=COALESCE(revoked_by,?),version=version+1,updated_at=? WHERE account_id=? AND status<>'PURGED'",time(now),bytes(account.id()),time(now),bytes(account.id()));
        jdbc.update("UPDATE user_account SET status='PURGED',display_name='Deleted account',purged_at=?,retain_until=NULL,blacklist_until=NULL,restriction_id=NULL,lifecycle_version=lifecycle_version+1,updated_at=? WHERE id=?",time(now),time(now),bytes(account.id()));
        if(jdbc.queryForObject("SELECT COUNT(*) FROM user_account WHERE user_id=? AND status<>'PURGED'",Integer.class,bytes(account.userId()))==0) {
            jdbc.update("DELETE FROM user_profile WHERE user_id=?",bytes(account.userId()));
            jdbc.update("DELETE FROM user_contact WHERE user_id=?",bytes(account.userId()));
            jdbc.update("DELETE FROM user_preference WHERE user_id=?",bytes(account.userId()));
            jdbc.update("UPDATE users SET display_name='Deleted user',status='DISABLED',updated_at=? WHERE id=?",time(now),bytes(account.userId()));
            jdbc.update("UPDATE account_group SET status='DISABLED',updated_at=? WHERE user_id=?",time(now),bytes(account.userId()));
        }
    }
    public void purgeRestriction(Restriction restriction,Instant now) {
        for(UUID id:affectedAccounts(restriction.organizationId(),restriction.userId())) purge(account(id,true).orElseThrow(),now);
        jdbc.update("DELETE gm FROM group_membership gm JOIN organization_membership m ON m.id=gm.organization_membership_id WHERE m.restriction_id=?",bytes(restriction.id()));
        jdbc.update("DELETE jr FROM group_join_request jr JOIN organization_membership m ON m.id=jr.organization_membership_id WHERE m.restriction_id=?",bytes(restriction.id()));
        jdbc.update("DELETE gi FROM group_invitation gi JOIN organization_membership m ON m.id=gi.organization_membership_id WHERE m.restriction_id=?",bytes(restriction.id()));
        jdbc.update("DELETE e FROM student_enrollment e JOIN organization_membership m ON m.id=e.organization_membership_id WHERE m.restriction_id=?",bytes(restriction.id()));
        jdbc.update("""
            UPDATE organization_membership SET status='PURGED',official_email='deleted',member_code=NULL,external_identity=NULL,version=version+1,updated_at=? WHERE restriction_id=? AND status='REVOKED'
            """,time(now),bytes(restriction.id()));
        jdbc.update("UPDATE organization_account_restriction SET status='PURGED',retain_until=NULL,version=version+1,updated_at=? WHERE id=?",time(now),bytes(restriction.id()));
        jdbc.update("DELETE FROM account_security_notice WHERE organization_id=? AND user_id=?",bytes(restriction.organizationId()),bytes(restriction.userId()));
        jdbc.update("UPDATE organization_invitation v JOIN organization_membership m ON m.id=v.membership_id SET v.official_email='deleted',v.token_hash=REPEAT('0',64) WHERE m.restriction_id=?",bytes(restriction.id()));
        jdbc.update("UPDATE organization_membership SET restriction_id=NULL WHERE restriction_id=? AND status='PURGED'",bytes(restriction.id()));
    }
    public static UUID id(ResultSet rs,String name) throws SQLException {
        byte[] value=rs.getBytes(name); if(value==null) return null;
        ByteBuffer buffer=ByteBuffer.wrap(value); return new UUID(buffer.getLong(),buffer.getLong());
    }
    public static Timestamp time(Instant value) { return value==null?null:Timestamp.from(value); }
    public static Instant instant(ResultSet rs,String name) throws SQLException { Timestamp value=rs.getTimestamp(name); return value==null?null:value.toInstant(); }
}
