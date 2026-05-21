package com.unidocs.auth.student;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static com.unidocs.auth.group.persistence.GroupRuleRepository.uuid;

/** Reconciliation reads committed intents; no user can acknowledge workspace readiness. */
@Service
public class StudentProvisioningService {
    public record Intent(UUID id,String kind,UUID organizationId,UUID semesterId,UUID workspaceId,
            UUID groupId,UUID accountId,UUID userId,Instant startsAt,Instant endsAt,long version) { }
    public record Contributor(UUID accountId,UUID membershipId,long version,String status) { }
    public record Contributors(UUID organizationId,long revision,List<Contributor> items,UUID nextCursor) { }
    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final OutboxRepository outbox;
    public StudentProvisioningService(JdbcTemplate jdbc,Clock clock,OutboxRepository outbox) { this.jdbc=jdbc;this.clock=clock;this.outbox=outbox; }
    @PreAuthorize("hasAuthority('SCOPE_iam.authorization.read')")
    @Transactional(readOnly=true)
    public Contributors contributors(Authentication service,UUID organization,UUID after,int limit) {
        service(service);if(organization==null||limit<1||limit>100) throw StudentWorkspaceService.bad();
        jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR SHARE",Long.class);
        Long revision=jdbc.query("SELECT authorization_version FROM organization WHERE id=? AND type='UNIVERSITY' AND status='ACTIVE' FOR SHARE",(row,index)->row.getLong(1),bytes(organization)).stream().findFirst().orElseThrow(StudentAuthorization::denied);
        List<Contributor> rows=jdbc.query("""
                SELECT s.account_id,s.membership_id,s.version+m.version version,
                IF(s.status IN('ACTIVE','COLLABORATION_RESTRICTED') AND m.status='ACTIVE' AND a.status='ACTIVE' AND u.status='ACTIVE'
                  AND EXISTS(SELECT 1 FROM student_admission d WHERE d.organization_id=s.organization_id AND d.membership_id=s.membership_id AND d.student_account_id=s.account_id AND d.status='APPROVED')
                  AND NOT EXISTS(SELECT 1 FROM iam_student_admin d WHERE d.organization_id=s.organization_id AND d.membership_id=s.membership_id AND d.status='ACTIVE')
                  AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=s.organization_id AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED','PURGED')),'ACTIVE','REVOKED') status
                FROM iam_student_state s JOIN organization_membership m ON m.id=s.membership_id AND m.organization_id=s.organization_id
                JOIN user_account a ON a.id=s.account_id JOIN users u ON u.id=a.user_id
                WHERE s.organization_id=? AND s.account_id>?
                ORDER BY s.account_id LIMIT ?
                """,(row,index)->new Contributor(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getLong(3),row.getString(4)),bytes(organization),bytes(after==null?new UUID(0,0):after),limit+1);
        List<Contributor> page=rows.stream().limit(limit).toList();service(service);
        return new Contributors(organization,revision,page,rows.size()>limit?page.getLast().accountId():null);
    }
    @PreAuthorize("hasAuthority('SCOPE_iam.authorization.read')")
    @Transactional(readOnly=true)
    public List<Intent> pending(Authentication service,UUID after,int limit) {
        service(service);if(limit<1||limit>100) throw StudentWorkspaceService.bad();
        List<Intent> result=jdbc.query("""
                SELECT p.*,s.starts_at,s.ends_at,a.user_id FROM (
                  SELECT w.semester_id id,'SEMESTER' kind,w.organization_id,w.semester_id,w.workspace_id,NULL group_id,w.requested_by account_id,w.version
                    FROM iam_semester_workspace w WHERE w.status='PENDING'
                  UNION ALL SELECT o.group_id,'COURSE',o.organization_id,o.semester_id,o.group_id,o.group_id,g.created_by_account_id,o.version
                    FROM iam_course_offering o JOIN iam_group g ON g.id=o.group_id
                    JOIN iam_semester_workspace w ON w.semester_id=o.semester_id AND w.status='READY' WHERE o.workspace_status='PENDING' AND o.status<>'RETIRED'
                  UNION ALL SELECT g.id,'STUDY',g.organization_id,o.semester_id,g.id,g.id,g.owner_account_id,g.version
                    FROM iam_study_group g JOIN iam_course_offering o ON o.group_id=g.course_id AND o.workspace_status='READY'
                    WHERE g.workspace_status='PENDING' AND g.status='ACTIVE'
                ) p JOIN academic_semester s ON s.id=p.semester_id JOIN user_account a ON a.id=p.account_id
                WHERE p.id>? ORDER BY p.id LIMIT ?
                """,(row,index)->new Intent(uuid(row.getBytes("id")),row.getString("kind"),uuid(row.getBytes("organization_id")),uuid(row.getBytes("semester_id")),uuid(row.getBytes("workspace_id")),uuid(row.getBytes("group_id")),uuid(row.getBytes("account_id")),uuid(row.getBytes("user_id")),row.getTimestamp("starts_at").toInstant(),row.getTimestamp("ends_at").toInstant(),row.getLong("version")),bytes(after==null?new UUID(0,0):after),limit);
        service(service);return result;
    }
    @PreAuthorize("hasAuthority('SCOPE_iam.authorization.read')")
    @Transactional
    public void ready(Authentication service,String kind,UUID id,UUID workspace,long expectedVersion) {
        service(service);jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE",Long.class);
        String table;String idColumn;String statusColumn;
        switch(kind) {
            case "SEMESTER" -> { table="iam_semester_workspace";idColumn="semester_id";statusColumn="status"; }
            case "COURSE" -> { table="iam_course_offering";idColumn="group_id";statusColumn="workspace_status"; }
            case "STUDY" -> { table="iam_study_group";idColumn="id";statusColumn="workspace_status"; }
            default -> throw StudentWorkspaceService.bad();
        }
        String actor=kind.equals("SEMESTER")?"requested_by":kind.equals("STUDY")?"owner_account_id":"(SELECT created_by_account_id FROM iam_group WHERE id=iam_course_offering.group_id)";
        List<Ready> records=jdbc.query("SELECT organization_id,"+statusColumn+",version"+(kind.equals("SEMESTER")?",workspace_id":","+idColumn)+","+actor+" FROM "+table+" WHERE "+idColumn+"=? FOR UPDATE",
                (row,index)->new Ready(uuid(row.getBytes(1)),row.getString(2),row.getLong(3),uuid(row.getBytes(4)),uuid(row.getBytes(5))),bytes(id));
        if(records.size()!=1||!records.getFirst().workspace().equals(workspace)) throw StudentAuthorization.denied();
        Ready current=records.getFirst();if(current.status().equals("READY")) { service(service);return; }
        if(current.version()!=expectedVersion) throw StudentWorkspaceService.conflict();
        jdbc.update("UPDATE "+table+" SET "+statusColumn+"='READY',version=version+1 WHERE "+idColumn+"=?",bytes(id));
        jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
        jdbc.update("UPDATE organization SET authorization_version=authorization_version+1 WHERE id=?",bytes(current.organization()));
        Long version=jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(current.organization()));
        jdbc.update("INSERT INTO iam_student_audit VALUES(?,?,?,?,?,?,?,?)",bytes(UUID.randomUUID()),bytes(current.organization()),bytes(current.actor()),null,bytes(id),"STUDENT_WORKSPACE_READY",version,java.sql.Timestamp.from(clock.instant()));
        outbox.lifecycle("ORGANIZATION",current.organization(),version,"STUDENT_WORKSPACE_READY",null,current.organization(),null,clock.instant());service(service);
    }
    void service(Authentication authentication) {
        if(authentication!=SecurityContextHolder.getContext().getAuthentication()||!(authentication instanceof JwtAuthenticationToken token)
                ||!token.isAuthenticated()||token.getToken().getExpiresAt()==null||!clock.instant().isBefore(token.getToken().getExpiresAt())
                ||!("document-service".equals(token.getToken().getClaimAsString("azp"))||"document-service".equals(token.getName()))) {
            throw new OperationAuthorizationFailure(HttpStatus.FORBIDDEN,"STUDENT_SERVICE_NOT_ALLOWED");
        }
    }
    private record Ready(UUID organization,String status,long version,UUID workspace,UUID actor) { }
}
