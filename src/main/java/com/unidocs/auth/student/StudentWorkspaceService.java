package com.unidocs.auth.student;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;
import jakarta.validation.Validator;
import jakarta.validation.constraints.*;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static com.unidocs.auth.group.persistence.GroupRuleRepository.uuid;

@Service
@Transactional(propagation=Propagation.NEVER)
public class StudentWorkspaceService {
    public record SemesterCommand(@NotNull UUID accountId,@Pattern(regexp="[A-Za-z0-9._-]{1,32}") @NotNull String code,
            @NotNull Instant startsAt,@NotNull Instant endsAt) { }
    public record Semester(UUID id,UUID workspaceId,String code,Instant startsAt,Instant endsAt,String readiness,long version) { }
    public record CatalogCommand(@NotNull UUID accountId,@NotNull UUID semesterId,@NotNull UUID requestId,
            @NotBlank @Size(max=100) String name,@Pattern(regexp="DRAFT|OFFERED|FINALIZED|RETIRED") @NotNull String status,
            @PositiveOrZero long expectedVersion) { }
    public record Course(UUID id,UUID semesterId,String name,String status,String readiness,long version,boolean joined) { }
    public record StudyCommand(@NotNull UUID accountId,@NotNull UUID courseId,@NotNull UUID requestId,@NotBlank @Size(max=100) String name) { }
    public record Study(UUID id,UUID courseId,String name,UUID ownerAccountId,String status,Instant purgeAfter,long version) { }
    public record Invitation(UUID id,UUID groupId,UUID recipientAccountId,String status,Instant expiresAt,long version) { }
    public record ReportCommand(@NotNull UUID accountId,@NotNull UUID courseId,@NotNull UUID targetAccountId,
            @NotNull UUID requestId,@NotBlank @Size(max=512) String evidenceReference) {
        @Override public String toString() { return "StudentReportCommand[REDACTED]"; }
    }
    public record Report(UUID id,UUID courseId,UUID reporterAccountId,UUID targetAccountId,String status,long version) { }
    public record ReportDetail(Report report,String evidenceReference,String reviewEvidenceReference) {
        @Override public String toString() { return "StudentReportDetail[REDACTED]"; }
    }
    public record ReviewCommand(@NotNull UUID accountId,@Positive long expectedVersion,
            @NotBlank @Size(max=512) String evidenceReference,boolean escalate) {
        @Override public String toString() { return "StudentReviewCommand[REDACTED]"; }
    }
    public record Notice(UUID id,UUID aggregateId,String eventType,long version,Instant occurredAt) { }
    public record Member(UUID accountId,String displayName,long version,boolean owner) { }
    private final JdbcTemplate jdbc;
    private final SessionAccess access;
    private final StudentAuthorization authorization;
    private final OutboxRepository outbox;
    private final Validator validator;
    private final Clock clock;
    private final long noticeSeconds;
    public StudentWorkspaceService(JdbcTemplate jdbc,SessionAccess access,StudentAuthorization authorization,
            OutboxRepository outbox,Validator validator,Clock clock) {
        this(jdbc,access,authorization,outbox,validator,clock,new org.springframework.core.env.StandardEnvironment());
    }
    @org.springframework.beans.factory.annotation.Autowired
    public StudentWorkspaceService(JdbcTemplate jdbc,SessionAccess access,StudentAuthorization authorization,
            OutboxRepository outbox,Validator validator,Clock clock,org.springframework.core.env.Environment environment) {
        this.jdbc=jdbc;this.access=access;this.authorization=authorization;this.outbox=outbox;this.validator=validator;this.clock=clock;
        long configured=environment.getProperty("auth.student-groups.test-notice-seconds",Long.class,604800L);
        noticeSeconds=java.util.Arrays.asList(environment.getActiveProfiles()).contains("test")?Math.max(2,Math.min(604800,configured)):604800;
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Semester semester(Jwt jwt,UUID organization,SemesterCommand command) {
        validate(command);
        if(!command.endsAt().isAfter(command.startsAt())||command.startsAt().getNano()%1000!=0||command.endsAt().getNano()%1000!=0
                ||command.startsAt().isBefore(Instant.parse("1000-01-01T00:00:00Z"))||!command.endsAt().isBefore(Instant.parse("+10000-01-01T00:00:00Z"))) throw bad();
        return execute(jwt,organization,command.accountId(),"semester.create",null,true,c->{
            List<Semester> previous=jdbc.query("SELECT s.*,w.workspace_id,w.status,w.version FROM academic_semester s LEFT JOIN iam_semester_workspace w ON w.semester_id=s.id WHERE s.organization_id=? AND s.code=?",
                    (row,index)->new Semester(uuid(row.getBytes("id")),uuid(row.getBytes("workspace_id")),row.getString("code"),row.getTimestamp("starts_at").toInstant(),row.getTimestamp("ends_at").toInstant(),row.getString("status"),row.getLong("version")),bytes(organization),command.code());
            if(!previous.isEmpty()) {
                Semester old=previous.getFirst();if(!old.startsAt().equals(command.startsAt())||!old.endsAt().equals(command.endsAt())) throw conflict();
                if(old.workspaceId()!=null) return old;
                UUID workspace=UUID.randomUUID();
                jdbc.update("INSERT INTO iam_semester_workspace(semester_id,organization_id,workspace_id,requested_by) VALUES(?,?,?,?)",bytes(old.id()),bytes(organization),bytes(workspace),bytes(command.accountId()));
                outbox.studentWorkspace(old.id(),organization,workspace,command.accountId(),c.owner().userId(),old.startsAt(),old.endsAt(),c.now());
                changed(c,organization,command.accountId(),old.id(),"STUDENT_SEMESTER_RECONCILED",null);
                return new Semester(old.id(),workspace,old.code(),old.startsAt(),old.endsAt(),"PENDING",1);
            }
            if(!command.endsAt().isAfter(clock.instant())) throw bad();
            UUID semester=UUID.randomUUID();UUID workspace=UUID.randomUUID();
            jdbc.update("INSERT INTO academic_semester(id,organization_id,code,starts_at,ends_at) VALUES(?,?,?,?,?)",bytes(semester),bytes(organization),command.code(),time(command.startsAt()),time(command.endsAt()));
            jdbc.update("INSERT INTO iam_semester_workspace(semester_id,organization_id,workspace_id,requested_by) VALUES(?,?,?,?)",bytes(semester),bytes(organization),bytes(workspace),bytes(command.accountId()));
            outbox.studentWorkspace(semester,organization,workspace,command.accountId(),c.owner().userId(),command.startsAt(),command.endsAt(),c.now());
            changed(c,organization,command.accountId(),semester,"STUDENT_SEMESTER_CREATED",null);
            return new Semester(semester,workspace,command.code(),command.startsAt(),command.endsAt(),"PENDING",1);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public List<Semester> semesters(Jwt jwt,UUID organization,UUID account,UUID after,int limit) {
        page(limit);return execute(jwt,organization,account,"course.catalog.read",null,false,c->jdbc.query("SELECT s.id,w.workspace_id,s.code,s.starts_at,s.ends_at,COALESCE(w.status,'PENDING'),COALESCE(w.version,1) FROM academic_semester s LEFT JOIN iam_semester_workspace w ON w.semester_id=s.id WHERE s.organization_id=? AND s.id>? ORDER BY s.id LIMIT ?",
                (row,index)->new Semester(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getString(3),row.getTimestamp(4).toInstant(),row.getTimestamp(5).toInstant(),row.getString(6),row.getLong(7)),bytes(organization),cursor(after),limit));
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Course catalog(Jwt jwt,UUID organization,UUID id,CatalogCommand command) {
        validate(command);name(command.name());
        return execute(jwt,organization,command.accountId(),id==null?"course.catalog.create":command.status().equals("RETIRED")?"course.catalog.remove":"course.catalog.update",null,true,c->{
            List<Window> windows=jdbc.query("SELECT starts_at,ends_at FROM academic_semester WHERE organization_id=? AND id=? FOR UPDATE",(row,index)->new Window(row.getTimestamp(1).toInstant(),row.getTimestamp(2).toInstant()),bytes(organization),bytes(command.semesterId()));
            if(windows.size()!=1) throw bad();Window window=windows.getFirst();
            if(id==null) {
                List<UUID> previous=jdbc.query("SELECT id FROM iam_group WHERE organization_id=? AND created_by_account_id=? AND creation_request_id=?",(row,index)->uuid(row.getBytes(1)),bytes(organization),bytes(command.accountId()),bytes(command.requestId()));
                if(!previous.isEmpty()) {
                    Course old=course(organization,previous.getFirst(),command.accountId());
                    if(!old.semesterId().equals(command.semesterId())||!old.name().equals(command.name().strip())||!old.status().equals(command.status())) throw conflict();return old;
                }
                if(command.expectedVersion()!=0||!clock.instant().isBefore(window.end())||!List.of("DRAFT","OFFERED").contains(command.status())
                        ||command.status().equals("DRAFT")&&!clock.instant().isBefore(window.start())) throw conflict();
                UUID group=UUID.randomUUID();Timestamp now=time(c.now());
                jdbc.update("INSERT INTO iam_group(id,organization_id,name,type,status,version,created_by_account_id,creation_request_id,creation_fingerprint,created_at,updated_at) VALUES(?,?,?,'COURSE','ACTIVE',1,?,?,?,?,?)",
                        bytes(group),bytes(organization),command.name().strip(),bytes(command.accountId()),bytes(command.requestId()),fingerprint(command.semesterId()+":"+command.name().strip()),now,now);
                jdbc.update("INSERT INTO group_rule(group_id,organization_id,discovery_scope,join_rule,semester_id,version) VALUES(?,?,'ORGANIZATION','COURSE_ENROLLMENT',?,1)",bytes(group),bytes(organization),bytes(command.semesterId()));
                jdbc.update("INSERT INTO iam_course_offering(group_id,organization_id,semester_id,status) VALUES(?,?,?,?)",bytes(group),bytes(organization),bytes(command.semesterId()),command.status());
                changed(c,organization,command.accountId(),group,"STUDENT_COURSE_CREATED",null);return course(organization,group,command.accountId());
            }
            Course old=course(organization,id,command.accountId());
            if(old.version()!=command.expectedVersion()||!old.semesterId().equals(command.semesterId())||!StudentRules.catalogMutable(old.status(),window.start(),clock.instant())) throw conflict();
            jdbc.update("UPDATE iam_course_offering SET status=?,version=version+1 WHERE group_id=?",command.status(),bytes(id));
            jdbc.update("UPDATE iam_group SET name=?,version=version+1,updated_at=? WHERE id=?",command.name().strip(),time(c.now()),bytes(id));
            changed(c,organization,command.accountId(),id,"STUDENT_COURSE_CHANGED",null);return course(organization,id,command.accountId());
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public List<Course> courses(Jwt jwt,UUID organization,UUID account,UUID after,int limit) {
        page(limit);return execute(jwt,organization,account,"course.catalog.read",null,false,c->jdbc.query("""
                SELECT g.id,o.semester_id,g.name,o.status,IF(o.workspace_status='READY',w.status,'PENDING') readiness,o.version,
                EXISTS(SELECT 1 FROM iam_student_course joined WHERE joined.group_id=g.id AND joined.account_id=?) joined
                FROM iam_course_offering o JOIN iam_group g ON g.id=o.group_id
                JOIN academic_semester s ON s.id=o.semester_id JOIN iam_semester_workspace w ON w.semester_id=s.id
                WHERE o.organization_id=? AND g.status='ACTIVE' AND g.id>?
                AND (EXISTS(SELECT 1 FROM iam_student_admin a WHERE a.organization_id=o.organization_id AND a.account_id=? AND a.status='ACTIVE')
                OR o.status IN('OFFERED','FINALIZED') AND w.status='READY' AND s.starts_at<=? AND s.ends_at>?
                OR EXISTS(SELECT 1 FROM iam_student_course c WHERE c.group_id=o.group_id AND c.account_id=?))
                ORDER BY g.id LIMIT ?
                """,(row,index)->new Course(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getString(3),row.getString(4),row.getString(5),row.getLong(6),row.getBoolean(7)),bytes(account),bytes(organization),cursor(after),bytes(account),time(clock.instant()),time(clock.instant()),bytes(account),limit));
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Course join(Jwt jwt,UUID organization,UUID account,UUID course) {
        return execute(jwt,organization,account,"course.join",null,true,c->{
            StudentAuthorization.Student student=authorization.student(organization,account);
            List<Boolean> offered=jdbc.query("SELECT o.status,IF(o.workspace_status='READY',w.status,'PENDING') readiness,s.starts_at,s.ends_at FROM iam_course_offering o JOIN academic_semester s ON s.id=o.semester_id JOIN iam_semester_workspace w ON w.semester_id=s.id JOIN iam_group g ON g.id=o.group_id AND g.status='ACTIVE' WHERE o.organization_id=? AND o.group_id=? FOR UPDATE",
                    (row,index)->StudentRules.joinable(row.getString("status"),row.getString("readiness"),row.getTimestamp("starts_at").toInstant(),row.getTimestamp("ends_at").toInstant(),clock.instant()),bytes(organization),bytes(course));
            if(offered.size()!=1||!offered.getFirst()) throw StudentAuthorization.denied();
            int created=jdbc.update("INSERT IGNORE INTO iam_student_course(organization_id,group_id,membership_id,account_id,id,joined_at) VALUES(?,?,?,?,?,?)",bytes(organization),bytes(course),bytes(student.membershipId()),bytes(account),bytes(UUID.randomUUID()),time(c.now()));
            if(created==1) changed(c,organization,account,course,"STUDENT_COURSE_JOINED",account);
            return course(organization,course,account);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Study createStudy(Jwt jwt,UUID organization,StudyCommand command) {
        validate(command);name(command.name());return execute(jwt,organization,command.accountId(),"study.group.create",command.courseId(),true,c->{
            List<UUID> previous=jdbc.query("SELECT id FROM iam_study_group WHERE owner_account_id=? AND request_id=?",(row,index)->uuid(row.getBytes(1)),bytes(command.accountId()),bytes(command.requestId()));
            if(!previous.isEmpty()) {
                Study old=study(organization,previous.getFirst());if(!old.courseId().equals(command.courseId())||!old.name().equals(command.name().strip())) throw conflict();return old;
            }
            UUID group=UUID.randomUUID();
            jdbc.update("INSERT INTO iam_study_group(id,organization_id,course_id,owner_account_id,name,request_id) VALUES(?,?,?,?,?,?)",bytes(group),bytes(organization),bytes(command.courseId()),bytes(command.accountId()),command.name().strip(),bytes(command.requestId()));
            jdbc.update("INSERT INTO iam_study_member(group_id,account_id,id,status) VALUES(?,?,?,'ACTIVE')",bytes(group),bytes(command.accountId()),bytes(UUID.randomUUID()));
            changed(c,organization,command.accountId(),group,"STUDY_GROUP_CREATED",command.accountId());return study(organization,group);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public List<Study> studies(Jwt jwt,UUID organization,UUID account,UUID course,UUID after,int limit) {
        page(limit);return execute(jwt,organization,account,"group.read",course,false,c->jdbc.query("SELECT s.* FROM iam_study_group s JOIN iam_study_member m ON m.group_id=s.id AND m.account_id=? AND m.status='ACTIVE' WHERE s.organization_id=? AND s.course_id=? AND s.id>? AND (s.status IN('ACTIVE','PREPARING') OR s.status='CLOSING' AND s.purge_after>?) ORDER BY s.id LIMIT ?",
                (row,index)->new Study(uuid(row.getBytes("id")),uuid(row.getBytes("course_id")),row.getString("name"),uuid(row.getBytes("owner_account_id")),row.getString("status"),row.getTimestamp("purge_after")==null?null:row.getTimestamp("purge_after").toInstant(),row.getLong("version")),bytes(account),bytes(organization),bytes(course),cursor(after),time(clock.instant()),limit));
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Invitation invite(Jwt jwt,UUID organization,UUID account,UUID group,UUID recipient,UUID request) {
        if(recipient==null||request==null||recipient.equals(account)) throw bad();
        return execute(jwt,organization,account,"group.invitation.issue",group,true,c->{
            owner(organization,group,account);authorization.recipient(organization,group,recipient,"EDIT");
            List<Invitation> old=jdbc.query("SELECT * FROM iam_study_invitation WHERE group_id=? AND request_id=?",(row,index)->invitation(row),bytes(group),bytes(request));
            if(!old.isEmpty()) { if(!old.getFirst().recipientAccountId().equals(recipient)) throw conflict();return old.getFirst(); }
            jdbc.update("UPDATE iam_study_invitation SET status='REVOKED',version=version+1 WHERE group_id=? AND recipient_account_id=? AND status='PENDING' AND expires_at<=?",bytes(group),bytes(recipient),time(clock.instant()));
            if(Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_study_invitation WHERE group_id=? AND recipient_account_id=? AND status='PENDING') OR EXISTS(SELECT 1 FROM iam_study_member WHERE group_id=? AND account_id=? AND status='ACTIVE')",Boolean.class,bytes(group),bytes(recipient),bytes(group),bytes(recipient)))) throw conflict();
            UUID id=UUID.randomUUID();Instant deadline=c.now().plusSeconds(604800);
            jdbc.update("INSERT INTO iam_study_invitation(id,group_id,recipient_account_id,request_id,expires_at) VALUES(?,?,?,?,?)",bytes(id),bytes(group),bytes(recipient),bytes(request),time(deadline));
            changed(c,organization,account,group,"STUDY_INVITATION_ISSUED",recipient);return new Invitation(id,group,recipient,"PENDING",deadline,1);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Invitation respond(Jwt jwt,UUID organization,UUID account,UUID id,boolean accept) {
        return execute(jwt,organization,account,accept?"group.invitation.accept":"group.invitation.decline",null,true,c->{
            Invitation invitation=jdbc.query("SELECT i.* FROM iam_study_invitation i JOIN iam_study_group g ON g.id=i.group_id WHERE i.id=? AND i.recipient_account_id=? AND g.organization_id=? AND g.status='ACTIVE' FOR UPDATE",(row,index)->invitation(row),bytes(id),bytes(account),bytes(organization)).stream().findFirst().orElseThrow(StudentAuthorization::denied);
            if(invitation.status().equals(accept?"ACCEPTED":"DECLINED")) return invitation;
            if(!invitation.status().equals("PENDING")||!clock.instant().isBefore(invitation.expiresAt())) throw conflict();
            if(accept) {
                authorization.recipient(organization,invitation.groupId(),account,"EDIT");
                jdbc.update("INSERT INTO iam_study_member(group_id,account_id,id,status) VALUES(?,?,?,'ACTIVE') ON DUPLICATE KEY UPDATE status='ACTIVE',version=version+1",bytes(invitation.groupId()),bytes(account),bytes(UUID.randomUUID()));
            }
            jdbc.update("UPDATE iam_study_invitation SET status=?,version=version+1 WHERE id=?",accept?"ACCEPTED":"DECLINED",bytes(id));
            changed(c,organization,account,invitation.groupId(),accept?"STUDY_INVITATION_ACCEPTED":"STUDY_INVITATION_DECLINED",account);
            return new Invitation(id,invitation.groupId(),account,accept?"ACCEPTED":"DECLINED",invitation.expiresAt(),invitation.version()+1);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public List<Invitation> invitations(Jwt jwt,UUID organization,UUID account,UUID after,int limit) {
        page(limit);return execute(jwt,organization,account,"group.read",null,false,c->jdbc.query("""
                SELECT i.* FROM iam_study_invitation i JOIN iam_study_group g ON g.id=i.group_id
                JOIN iam_course_offering o ON o.group_id=g.course_id JOIN academic_semester s ON s.id=o.semester_id
                WHERE g.organization_id=? AND i.recipient_account_id=? AND i.id>? AND i.status='PENDING'
                AND g.status='ACTIVE' AND i.expires_at>? AND s.starts_at<=? AND s.ends_at>?
                AND EXISTS(SELECT 1 FROM iam_student_course c WHERE c.group_id=g.course_id AND c.account_id=i.recipient_account_id)
                ORDER BY i.id LIMIT ?
                """,(row,index)->invitation(row),bytes(organization),bytes(account),cursor(after),time(clock.instant()),time(clock.instant()),time(clock.instant()),limit));
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public List<Member> members(Jwt jwt,UUID organization,UUID account,UUID group,UUID after,int limit) {
        page(limit);return execute(jwt,organization,account,"group.read",group,false,c->jdbc.query("""
                SELECT m.account_id,a.display_name,m.version,g.owner_account_id=m.account_id FROM iam_study_member m
                JOIN iam_study_group g ON g.id=m.group_id JOIN user_account a ON a.id=m.account_id AND a.status='ACTIVE'
                JOIN iam_student_state s ON s.organization_id=g.organization_id AND s.account_id=m.account_id AND s.status IN('ACTIVE','COLLABORATION_RESTRICTED')
                JOIN organization_membership om ON om.id=s.membership_id AND om.status='ACTIVE'
                WHERE g.id=? AND g.organization_id=? AND m.status='ACTIVE' AND m.account_id>?
                AND EXISTS(SELECT 1 FROM iam_student_course c WHERE c.group_id=g.course_id AND c.membership_id=om.id)
                ORDER BY m.account_id LIMIT ?
                """,(row,index)->new Member(uuid(row.getBytes(1)),row.getString(2),row.getLong(3),row.getBoolean(4)),bytes(group),bytes(organization),cursor(after),limit));
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Invitation revokeInvitation(Jwt jwt,UUID organization,UUID account,UUID group,UUID id,long expectedVersion) {
        if(expectedVersion<1) throw bad();return execute(jwt,organization,account,"group.invitation.revoke",group,true,c->{
            owner(organization,group,account);
            Invitation current=jdbc.query("SELECT * FROM iam_study_invitation WHERE id=? AND group_id=? FOR UPDATE",(row,index)->invitation(row),bytes(id),bytes(group)).stream().findFirst().orElseThrow(StudentAuthorization::denied);
            if(current.status().equals("REVOKED")&&current.version()==expectedVersion+1) return current;
            if(!current.status().equals("PENDING")||current.version()!=expectedVersion) throw conflict();
            jdbc.update("UPDATE iam_study_invitation SET status='REVOKED',version=version+1 WHERE id=?",bytes(id));
            changed(c,organization,account,group,"STUDY_INVITATION_REVOKED",current.recipientAccountId());
            return new Invitation(id,group,current.recipientAccountId(),"REVOKED",current.expiresAt(),current.version()+1);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Study deletion(Jwt jwt,UUID organization,UUID account,UUID group,long expectedVersion,boolean cancel) {
        return execute(jwt,organization,account,cancel?"group.delete.cancel":"group.delete.schedule",group,true,c->{
            Study old=owner(organization,group,account);if(old.version()!=expectedVersion) throw conflict();
            if(cancel) {
                if(old.status().equals("ACTIVE")) return old;
                if(old.purgeAfter()!=null&&!clock.instant().isBefore(old.purgeAfter())) throw conflict();
                jdbc.update("UPDATE iam_study_group SET status='ACTIVE',notice_batch_id=NULL,purge_after=NULL,deletion_requested_at=NULL,version=version+1 WHERE id=?",bytes(group));
            } else {
                if(!old.status().equals("ACTIVE")) return old;
                if(noticeSeconds!=604800) {
                    String database=jdbc.queryForObject("SELECT DATABASE()",String.class);
                    if(database==null||!database.equalsIgnoreCase("auth_service_test")) throw bad();
                }
                jdbc.update("UPDATE iam_study_group SET status='PREPARING',deletion_requested_at=?,deletion_notice_seconds=?,version=version+1 WHERE id=?",time(c.now()),noticeSeconds,bytes(group));
            }
            changed(c,organization,account,group,cancel?"STUDY_DELETION_CANCELLED":"STUDY_DELETION_PREPARING",null);return study(organization,group);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public void leave(Jwt jwt,UUID organization,UUID account,UUID group) {
        execute(jwt,organization,account,"group.leave",group,true,c->{
            if(study(organization,group).ownerAccountId().equals(account)) throw conflict();
            jdbc.update("UPDATE iam_study_member SET status='REVOKED',version=version+1 WHERE group_id=? AND account_id=? AND status='ACTIVE'",bytes(group),bytes(account));
            changed(c,organization,account,group,"STUDY_GROUP_LEFT",account);return true;
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Report report(Jwt jwt,UUID organization,ReportCommand command) {
        validate(command);evidence(command.evidenceReference());
        return execute(jwt,organization,command.accountId(),"student.report.submit",command.courseId(),true,c->{
            authorization.course(organization,command.courseId(),command.targetAccountId(),"file.read");
            List<Report> old=jdbc.query("SELECT * FROM iam_student_report WHERE reporter_account_id=? AND request_id=?",(row,index)->report(row),bytes(command.accountId()),bytes(command.requestId()));
            if(!old.isEmpty()) {
                Report prior=old.getFirst();String proof=jdbc.queryForObject("SELECT evidence_reference FROM iam_student_report WHERE id=?",String.class,bytes(prior.id()));
                if(!prior.courseId().equals(command.courseId())||!prior.targetAccountId().equals(command.targetAccountId())||!command.evidenceReference().equals(proof)) throw conflict();return prior;
            }
            requireEvidence(organization,command.accountId(),command.courseId(),null,command.evidenceReference());
            UUID id=UUID.randomUUID();jdbc.update("INSERT INTO iam_student_report(id,organization_id,course_id,reporter_account_id,target_account_id,evidence_reference,request_id) VALUES(?,?,?,?,?,?,?)",bytes(id),bytes(organization),bytes(command.courseId()),bytes(command.accountId()),bytes(command.targetAccountId()),command.evidenceReference(),bytes(command.requestId()));
            jdbc.update("UPDATE iam_student_report_evidence SET report_id=? WHERE id=?",bytes(id),bytes(UUID.fromString(command.evidenceReference())));
            changed(c,organization,command.accountId(),id,"STUDENT_REPORT_SUBMITTED",command.accountId());
            return new Report(id,command.courseId(),command.accountId(),command.targetAccountId(),"SUBMITTED",1);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public List<Report> reports(Jwt jwt,UUID organization,UUID account,UUID after,int limit) {
        page(limit);return execute(jwt,organization,account,"student.report.review",null,false,c->jdbc.query("SELECT * FROM iam_student_report WHERE organization_id=? AND id>? ORDER BY id LIMIT ?",(row,index)->report(row),bytes(organization),cursor(after),limit));
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public ReportDetail reportDetail(Jwt jwt,UUID organization,UUID account,UUID id) {
        return execute(jwt,organization,account,"student.report.review",null,false,c->jdbc.query("SELECT * FROM iam_student_report WHERE organization_id=? AND id=?",(row,index)->new ReportDetail(report(row),row.getString("evidence_reference"),row.getString("review_evidence_reference")),bytes(organization),bytes(id)).stream().findFirst().orElseThrow(StudentAuthorization::denied));
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Report review(Jwt jwt,UUID organization,UUID id,ReviewCommand command) {
        validate(command);evidence(command.evidenceReference());
        return execute(jwt,organization,command.accountId(),command.escalate()?"student.report.evidence.submit":"student.report.review",null,true,c->{
            Report old=jdbc.query("SELECT * FROM iam_student_report WHERE organization_id=? AND id=? FOR UPDATE",(row,index)->report(row),bytes(organization),bytes(id)).stream().findFirst().orElseThrow(StudentAuthorization::denied);
            if(old.version()!=command.expectedVersion()||!old.status().equals(command.escalate()?"REVIEWED":"SUBMITTED")||old.targetAccountId().equals(command.accountId())||old.reporterAccountId().equals(command.accountId())) throw conflict();
            requireEvidence(organization,command.accountId(),old.courseId(),id,command.evidenceReference());
            jdbc.update("UPDATE iam_student_report SET status=?,review_evidence_reference=?,reviewed_by=?,version=version+1 WHERE id=?",command.escalate()?"ESCALATED":"REVIEWED",command.evidenceReference(),bytes(command.accountId()),bytes(id));
            changed(c,organization,command.accountId(),id,command.escalate()?"STUDENT_REPORT_ESCALATED":"STUDENT_REPORT_REVIEWED",old.reporterAccountId());
            return new Report(id,old.courseId(),old.reporterAccountId(),old.targetAccountId(),command.escalate()?"ESCALATED":"REVIEWED",old.version()+1);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public List<Notice> notices(Jwt jwt,UUID organization,UUID account,UUID after,int limit) {
        page(limit);return execute(jwt,organization,account,"course.catalog.read",null,false,c->jdbc.query("SELECT id,aggregate_id,event_type,authorization_version,occurred_at FROM iam_student_notice WHERE organization_id=? AND recipient_account_id=? AND id>? ORDER BY id LIMIT ?",
                (row,index)->new Notice(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getString(3),row.getLong(4),row.getTimestamp(5).toInstant()),bytes(organization),bytes(account),cursor(after),limit));
    }
    private <T> T execute(Jwt jwt,UUID organization,UUID account,String operation,UUID group,boolean mutation,Function<SessionAccess.Context,T> work) {
        if(jwt==null||account==null||organization==null) throw bad();
        return access.execute(UUID.fromString(jwt.getClaimAsString("sid")),UUID.fromString(jwt.getSubject()),c->{
            token(jwt);if(mutation) fence(organization);
            authorization.require(c,account,organization,group,"auth-service",operation);T result=work.apply(c);token(jwt);return result;
        });
    }
    @Transactional(propagation=Propagation.MANDATORY)
    void fence(UUID organization) {
        jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE",Long.class);
        List<UUID> found=jdbc.query("SELECT id FROM organization WHERE id=? AND type='UNIVERSITY' AND status='ACTIVE' FOR UPDATE",(row,index)->uuid(row.getBytes(1)),bytes(organization));
        if(found.size()!=1) throw StudentAuthorization.denied();
    }
    @Transactional(propagation=Propagation.MANDATORY)
    long changed(SessionAccess.Context context,UUID organization,UUID actor,UUID aggregate,String event,UUID target) {
        jdbc.update("UPDATE organization SET authorization_version=authorization_version+1,updated_at=? WHERE id=?",time(context.now()),bytes(organization));
        jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
        Long version=jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(organization));
        jdbc.update("INSERT INTO iam_student_audit VALUES(?,?,?,?,?,?,?,?)",bytes(UUID.randomUUID()),bytes(organization),bytes(actor),bytes(context.session().id()),bytes(aggregate),event,version,time(context.now()));
        jdbc.update("INSERT INTO iam_student_notice SELECT UUID_TO_BIN(UUID()),organization_id,account_id,?,?,?,? FROM organization_membership WHERE organization_id=? AND ((? IS NULL AND status='ACTIVE') OR account_id=?)",bytes(aggregate),event,version,time(context.now()),bytes(organization),nullable(target),nullable(target));
        outbox.lifecycle("ORGANIZATION",organization,version,event,target,organization,null,context.now());
        Long global=jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL'",Long.class);
        outbox.lifecycle("IAM_POLICY",organization,global,"IAM_POLICY_CHANGED",actor,organization,null,context.now());return version;
    }
    private Course course(UUID organization,UUID id,UUID account) {
        return jdbc.query("SELECT g.id,o.semester_id,g.name,o.status,IF(o.workspace_status='READY',w.status,'PENDING') readiness,o.version,EXISTS(SELECT 1 FROM iam_student_course c WHERE c.group_id=g.id AND c.account_id=?) joined FROM iam_course_offering o JOIN iam_group g ON g.id=o.group_id JOIN iam_semester_workspace w ON w.semester_id=o.semester_id WHERE o.organization_id=? AND g.id=?",
                (row,index)->new Course(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getString(3),row.getString(4),row.getString(5),row.getLong(6),row.getBoolean(7)),bytes(account),bytes(organization),bytes(id)).stream().findFirst().orElseThrow(StudentAuthorization::denied);
    }
    private Study study(UUID organization,UUID id) {
        return jdbc.query("SELECT * FROM iam_study_group WHERE organization_id=? AND id=?",(row,index)->new Study(id,uuid(row.getBytes("course_id")),row.getString("name"),uuid(row.getBytes("owner_account_id")),row.getString("status"),row.getTimestamp("purge_after")==null?null:row.getTimestamp("purge_after").toInstant(),row.getLong("version")),bytes(organization),bytes(id)).stream().findFirst().orElseThrow(StudentAuthorization::denied);
    }
    private Study owner(UUID organization,UUID group,UUID account) {
        Study value=study(organization,group);if(!value.ownerAccountId().equals(account)) throw StudentAuthorization.denied();return value;
    }
    private static Invitation invitation(java.sql.ResultSet row) throws java.sql.SQLException {
        return new Invitation(uuid(row.getBytes("id")),uuid(row.getBytes("group_id")),uuid(row.getBytes("recipient_account_id")),row.getString("status"),row.getTimestamp("expires_at").toInstant(),row.getLong("version"));
    }
    private static Report report(java.sql.ResultSet row) throws java.sql.SQLException {
        return new Report(uuid(row.getBytes("id")),uuid(row.getBytes("course_id")),uuid(row.getBytes("reporter_account_id")),uuid(row.getBytes("target_account_id")),row.getString("status"),row.getLong("version"));
    }
    private void validate(Object command) { if(command==null||!validator.validate(command).isEmpty()) throw bad(); }
    private void requireEvidence(UUID organization,UUID actor,UUID course,UUID report,String reference) {
        UUID id;try { id=UUID.fromString(reference); } catch(IllegalArgumentException invalid) { throw bad(); }
        if(!id.toString().equals(reference)) throw bad();
        if(!Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_student_report_evidence WHERE id=? AND organization_id=? AND course_id=? AND uploaded_by=? AND report_id<=>? AND status='READY')",Boolean.class,bytes(id),bytes(organization),bytes(course),bytes(actor),nullable(report)))) throw StudentAuthorization.denied();
    }
    private void token(Jwt jwt) { if(jwt.getExpiresAt()==null||!clock.instant().isBefore(jwt.getExpiresAt())) throw new AuthenticationFailure(); }
    private static void name(String name) { if(name==null||name.isBlank()||name.strip().length()>100||name.codePoints().anyMatch(Character::isISOControl)) throw bad(); }
    static void evidence(String reference) { if(reference==null||!reference.matches("[A-Za-z0-9][A-Za-z0-9/_-]{0,511}")||reference.contains("..")) throw bad(); }
    private static void page(int limit) { if(limit<1||limit>100) throw bad(); }
    static Timestamp time(Instant value) { return Timestamp.from(value); }
    static byte[] nullable(UUID value) { return value==null?null:bytes(value); }
    private static byte[] cursor(UUID value) { return bytes(value==null?new UUID(0,0):value); }
    private static String fingerprint(String value) {
        try { return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8))); }
        catch(java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    private record Window(Instant start,Instant end) { }
    static OperationAuthorizationFailure bad() { return new OperationAuthorizationFailure(HttpStatus.BAD_REQUEST,"INVALID_STUDENT_COMMAND"); }
    static OperationAuthorizationFailure conflict() { return new OperationAuthorizationFailure(HttpStatus.CONFLICT,"STUDENT_VERSION_CONFLICT"); }
}
