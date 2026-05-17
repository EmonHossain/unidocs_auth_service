package com.unidocs.auth.student;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import com.unidocs.auth.group.personal.PersonalGroupClosureService.Closure;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static com.unidocs.auth.group.persistence.GroupRuleRepository.uuid;

/** Uses the same durable Document notice/copy/purge protocol as personal groups. */
@Service
public class StudentClosureService {
    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final StudentProvisioningService services;
    private final OutboxRepository outbox;
    public StudentClosureService(JdbcTemplate jdbc,Clock clock,StudentProvisioningService services,OutboxRepository outbox) {
        this.jdbc=jdbc;this.clock=clock;this.services=services;this.outbox=outbox;
    }
    @PreAuthorize("hasAuthority('SCOPE_iam.authorization.read')")
    @Transactional
    public List<Closure> closures(Authentication service,UUID after,int limit) {
        services.service(service);if(limit<1||limit>101) throw StudentWorkspaceService.bad();
        jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR SHARE",Long.class);
        List<Closure> result=jdbc.query(SELECT+" WHERE g.status IN('PREPARING','CLOSING') AND g.id>? ORDER BY g.id LIMIT ?",this::map,bytes(after==null?new UUID(0,0):after),limit);
        services.service(service);return result;
    }
    @PreAuthorize("hasAuthority('SCOPE_iam.authorization.read')")
    @Transactional
    public Closure state(Authentication service,UUID group) {
        services.service(service);jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR SHARE",Long.class);
        Closure result=read(group);services.service(service);return result;
    }
    @PreAuthorize("hasAuthority('SCOPE_iam.authorization.read')")
    @Transactional
    public Closure confirm(Authentication service,UUID group,long expectedVersion,UUID batch) {
        services.service(service);if(batch==null||expectedVersion<1) throw StudentWorkspaceService.bad();
        jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE",Long.class);
        List<Receipt> rows=jdbc.query("SELECT organization_id,notice_batch_id FROM iam_study_group WHERE id=? FOR UPDATE",(row,index)->new Receipt(uuid(row.getBytes(1)),uuid(row.getBytes(2))),bytes(group));
        if(rows.size()!=1) throw StudentAuthorization.denied();Receipt receipt=rows.getFirst();Closure before=read(group);
        if(before.status().equals("CLOSING")) { if(batch.equals(receipt.batch())) { services.service(service);return before; }throw StudentWorkspaceService.conflict(); }
        if(!before.status().equals("PREPARING")||before.groupVersion()!=expectedVersion) throw StudentWorkspaceService.conflict();
        Instant now=clock.instant(),deadline=now.plusSeconds(before.noticeSeconds());
        jdbc.update("UPDATE iam_study_group SET status='CLOSING',notice_batch_id=?,purge_after=?,version=version+1 WHERE id=?",bytes(batch),Timestamp.from(deadline),bytes(group));
        jdbc.update("UPDATE organization SET authorization_version=authorization_version+1 WHERE id=?",bytes(receipt.organization()));
        jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
        jdbc.update("INSERT INTO account_security_notice(id,user_id,account_id,code,reason,deadline,created_at,available_at) SELECT UUID_TO_BIN(UUID()),a.user_id,a.id,'STUDY_GROUP_DELETION_SCHEDULED','Copy authorized content before the stated deadline.',?,?,? FROM iam_study_member m JOIN user_account a ON a.id=m.account_id WHERE m.group_id=? AND m.status='ACTIVE'",Timestamp.from(deadline),Timestamp.from(now),Timestamp.from(now),bytes(group));
        Long version=jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(receipt.organization()));
        jdbc.update("INSERT INTO iam_student_audit VALUES(?,?,?,?,?,?,?,?)",bytes(UUID.randomUUID()),bytes(receipt.organization()),bytes(before.ownerAccountId()),null,bytes(group),"STUDY_GROUP_DELETION_SCHEDULED",version,Timestamp.from(now));
        outbox.lifecycle("ORGANIZATION",receipt.organization(),version,"STUDY_GROUP_DELETION_SCHEDULED",before.ownerAccountId(),receipt.organization(),deadline,now);
        services.service(service);return read(group);
    }
    private Closure read(UUID group) {
        return jdbc.query(SELECT+" WHERE g.id=?",this::map,bytes(group)).stream().findFirst().orElseThrow(StudentAuthorization::denied);
    }
    private static final String SELECT="SELECT g.*,a.user_id FROM iam_study_group g JOIN user_account a ON a.id=g.owner_account_id";
    private Closure map(java.sql.ResultSet row,int index) throws java.sql.SQLException {
        Instant now=clock.instant();Timestamp deadline=row.getTimestamp("purge_after"),requested=row.getTimestamp("deletion_requested_at");String status=row.getString("status");
        return new Closure(uuid(row.getBytes("id")),row.getLong("version"),uuid(row.getBytes("owner_account_id")),uuid(row.getBytes("user_id")),status,row.getLong("deletion_notice_seconds"),deadline==null?null:deadline.toInstant(),requested==null?null:requested.toInstant(),now,status.equals("CLOSING")&&deadline!=null&&!now.isBefore(deadline.toInstant()));
    }
    private record Receipt(UUID organization,UUID batch) { }
}
