package com.unidocs.auth.student;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.domain.UserSession;
import com.unidocs.auth.session.persistence.SessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Transactional;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Rollback-only SQL fixtures and mocked session collaborator; not real-session acceptance evidence. */
@SpringBootTest
@Transactional
class StudentAuthorizationIntegrationTests extends MySqlIntegrationTest {
    @Autowired StudentAuthorization authority;
    @Autowired JdbcTemplate jdbc;
    @Autowired com.unidocs.auth.outbox.persistence.OutboxRepository outbox;
    @Autowired jakarta.validation.Validator validator;
    @Autowired StudentClosureService closures;
    @Autowired org.springframework.transaction.PlatformTransactionManager transactions;
    @MockitoBean SessionRepository sessions;
    private UUID institution,student,user,member,course,semester,creator;
    private Instant now;
    private SessionAccess.Context context;
    @BeforeEach void fixture() {
        now=Instant.now();creator=account("PERSONAL",null,UUID.randomUUID());institution=UUID.randomUUID();user=UUID.randomUUID();
        jdbc.update("INSERT INTO organization(id,name,slug,type,status,authorization_version,created_by_account_id,creation_request_id,creation_fingerprint,created_at,updated_at) VALUES(?,'Institution',?,'UNIVERSITY','ACTIVE',1,?,?,REPEAT('a',64),?,?)",bytes(institution),"institute-"+institution,bytes(creator),bytes(UUID.randomUUID()),time(now),time(now));
        jdbc.update("INSERT INTO organization_auth_policy VALUES(?,?,'PASSWORD',NULL,TRUE,FALSE,FALSE,?,?)",bytes(UUID.randomUUID()),bytes(institution),time(now),time(now));
        student=account("UNIVERSITY",institution,user);UUID applicant=account("PERSONAL",null,user);member=UUID.randomUUID();
        jdbc.update("INSERT INTO organization_membership(id,organization_id,account_id,role,status,version,joined_at,created_at,updated_at) VALUES(?,?,?,'MEMBER','ACTIVE',1,?,?,?)",bytes(member),bytes(institution),bytes(student),time(now),time(now),time(now));
        jdbc.update("INSERT INTO student_admission(id,organization_id,applicant_account_id,applicant_user_id,account_group_id,email,method,status,password_hash,code_hash,code_expires_at,student_account_id,membership_id,created_at) VALUES(?,?,?,?,?,?,'INSTITUTE_EMAIL','APPROVED','unused-fixture-hash','unused-fixture-code-hash',?,?,?,?)",bytes(UUID.randomUUID()),bytes(institution),bytes(applicant),bytes(user),bytes(UUID.randomUUID()),"student-"+student+"@example.test",time(now.plusSeconds(300)),bytes(student),bytes(member),time(now));
        jdbc.update("INSERT INTO iam_student_state(organization_id,membership_id,account_id) VALUES(?,?,?)",bytes(institution),bytes(member),bytes(student));
        semester=UUID.randomUUID();course=UUID.randomUUID();
        jdbc.update("INSERT INTO academic_semester VALUES(?,?,?, ?,?)",bytes(semester),bytes(institution),"2026-"+semester.toString().substring(0,8),time(now.minusSeconds(60)),time(now.plusSeconds(600)));
        jdbc.update("INSERT INTO iam_semester_workspace(semester_id,organization_id,workspace_id,status,requested_by) VALUES(?,?,?,'READY',?)",bytes(semester),bytes(institution),bytes(UUID.randomUUID()),bytes(creator));
        jdbc.update("INSERT INTO iam_group(id,organization_id,name,type,status,version,created_by_account_id,creation_request_id,creation_fingerprint,created_at,updated_at) VALUES(?,?,'Course','COURSE','ACTIVE',1,?,?,REPEAT('b',64),?,?)",bytes(course),bytes(institution),bytes(creator),bytes(UUID.randomUUID()),time(now),time(now));
        jdbc.update("INSERT INTO iam_course_offering(group_id,organization_id,semester_id,status,workspace_status) VALUES(?,?,?,'OFFERED','READY')",bytes(course),bytes(institution),bytes(semester));
        jdbc.update("INSERT INTO iam_student_course(organization_id,group_id,membership_id,account_id,id,joined_at) VALUES(?,?,?,?,?,?)",bytes(institution),bytes(course),bytes(member),bytes(student),bytes(UUID.randomUUID()),time(now));
        UserSession session=new UserSession(UUID.randomUUID(),UUID.randomUUID(),student,"ACTIVE",now,now,now.plusSeconds(600),null);
        SessionAccountGrant grant=new SessionAccountGrant(session.id(),student,"ACTIVE","LOGIN",1,now.plusSeconds(600),now.plusSeconds(600));
        context=new SessionAccess.Context(session,new SessionRepository.Owner(user,"Student",student),grant,now);
        when(sessions.liveGrant(eq(session),eq(student),any())).thenReturn(Optional.of(grant));
    }
    @Test void verifiedJoinedStudentUsesOnlyStudentCategory() {
        assertThat(authority.require(context,student,institution,course,"document-service","file.read").categoryKey()).isEqualTo("STUDENT");
    }
    @Test void admissionWithoutCurrentVerificationCannotAuthorizeEvenAnExistingJoin() {
        jdbc.update("UPDATE student_admission SET status='REJECTED' WHERE student_account_id=?",bytes(student));
        denied("file.read",course);
    }
    @Test void sameSessionImmediatelySeesCategorySharingRemoval() {
        assertThat(authority.require(context,student,institution,course,"document-service","file.share.view").reasonCode()).isEqualTo("ALLOWED");
        jdbc.update("DELETE ra FROM iam_role_authority ra JOIN iam_stakeholder_role_binding b ON b.role_id=ra.role_id AND b.category_key='STUDENT' JOIN iam_authority a ON a.id=ra.authority_id AND a.service_id='document-service' AND a.authority_key='file.share'");
        jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
        denied("file.share.view",course);
        assertThat(authority.require(context,student,institution,course,"document-service","file.read").reasonCode()).isEqualTo("ALLOWED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_role_authority ra JOIN iam_stakeholder_role_binding b ON b.role_id=ra.role_id AND b.category_key='ORGANIZATION' JOIN iam_authority a ON a.id=ra.authority_id AND a.authority_key='file.share'",Integer.class)).isPositive();
    }
    @Test void restrictionBlocksExistingCollaborationButPreservesOwnRightsAndPublicReads() {
        jdbc.update("UPDATE iam_student_state SET status='COLLABORATION_RESTRICTED',version=version+1 WHERE account_id=?",bytes(student));
        for(String operation:java.util.List.of("file.share.view","file.share.edit","file.collaborative.edit")) denied(operation,course);
        for(String operation:java.util.List.of("file.read","file.create","file.edit","file.delete.schedule","file.copy","file.share.revoke"))
            assertThat(authority.require(context,student,institution,course,"document-service",operation).reasonCode()).isEqualTo("ALLOWED");
    }
    @Test void pendingWorkspaceAndWrongInstitutionFailClosed() {
        jdbc.update("UPDATE iam_semester_workspace SET status='PENDING' WHERE semester_id=?",bytes(semester));denied("file.read",course);
        assertThatThrownBy(()->authority.require(context,student,UUID.randomUUID(),null,"document-service","file.read")).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void uninvitedStudyGroupIsNotAReadableCourse() {
        UUID study=UUID.randomUUID();jdbc.update("INSERT INTO iam_study_group(id,organization_id,course_id,owner_account_id,name,request_id,workspace_status) VALUES(?,?,?,?,'Private study',?,'READY')",bytes(study),bytes(institution),bytes(course),bytes(creator),bytes(UUID.randomUUID()));
        denied("file.read",study);
    }
    @Test void appointedAdminHasNoStudentContentOrEnrollmentFallback() {
        jdbc.update("INSERT INTO iam_student_admin(organization_id,membership_id,account_id,role_id,status) SELECT ?,?,?,role_id,'ACTIVE' FROM iam_student_role_binding WHERE responsibility='STUDENT_ADMIN'",bytes(institution),bytes(member),bytes(student));
        assertThat(authority.require(context,student,institution,null,"auth-service","course.catalog.read").reasonCode()).isEqualTo("ALLOWED");
        denied("file.read",course);
        assertThatThrownBy(()->authority.require(context,student,institution,null,"auth-service","course.join")).isInstanceOf(OperationAuthorizationFailure.class);
        jdbc.update("UPDATE iam_student_role_binding SET status='DISABLED' WHERE responsibility='STUDENT_ADMIN'");
        assertThatThrownBy(()->authority.require(context,student,institution,null,"auth-service","course.catalog.read")).isInstanceOf(OperationAuthorizationFailure.class);
        denied("file.read",course);
    }
    @Test void archivedSemesterKeepsReadsButDeniesWrites() {
        jdbc.update("UPDATE academic_semester SET ends_at=? WHERE id=?",time(now.minusSeconds(1)),bytes(semester));
        assertThat(authority.require(context,student,institution,course,"document-service","file.read").reasonCode()).isEqualTo("ALLOWED");
        denied("file.create",course);denied("file.edit",course);
    }
    @Test void legacyOwnerRankCannotReplaceDeveloperAppointment() {
        jdbc.update("UPDATE organization_membership SET role='OWNER' WHERE id=?",bytes(member));
        assertThatThrownBy(()->authority.require(context,student,institution,null,"auth-service","student.admission.review")).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void verifiedStudentSelfJoinIsIdempotentAndDoesNotAssignOtherAccounts() {
        jdbc.update("DELETE FROM iam_student_course WHERE organization_id=?",bytes(institution));
        StudentWorkspaceService application=application();
        assertThat(application.join(jwt(),institution,student,course).joined()).isTrue();
        assertThat(application.join(jwt(),institution,student,course).joined()).isTrue();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_student_course WHERE organization_id=?",Integer.class,bytes(institution))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE aggregate_id=? AND event_type='STUDENT_COURSE_JOINED'",Integer.class,bytes(institution))).isEqualTo(1);
        assertThatThrownBy(()->application.join(jwt(),institution,creator,course)).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void selfJoinFailsWhileEitherWorkspaceIsPending() {
        jdbc.update("DELETE FROM iam_student_course WHERE organization_id=?",bytes(institution));
        jdbc.update("UPDATE iam_course_offering SET workspace_status='PENDING' WHERE group_id=?",bytes(course));
        assertThatThrownBy(()->application().join(jwt(),institution,student,course)).isInstanceOf(OperationAuthorizationFailure.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_student_course WHERE organization_id=?",Integer.class,bytes(institution))).isZero();
    }
    @Test void semesterCreationRetriesReturnOnePendingWorkspaceAndOneCommittedIntent() {
        administrator();StudentWorkspaceService application=application();
        Instant start=now.plusSeconds(60).truncatedTo(java.time.temporal.ChronoUnit.MICROS),end=start.plusSeconds(86400);
        StudentWorkspaceService.SemesterCommand command=new StudentWorkspaceService.SemesterCommand(student,"future-proof",start,end);
        StudentWorkspaceService.Semester first=application.semester(jwt(),institution,command);
        StudentWorkspaceService.Semester second=application.semester(jwt(),institution,command);
        assertThat(second.id()).isEqualTo(first.id());assertThat(second.workspaceId()).isEqualTo(first.workspaceId());assertThat(second.readiness()).isEqualTo("PENDING");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE aggregate_id=? AND event_type='STUDENT_SEMESTER_WORKSPACE_REQUESTED'",Integer.class,bytes(first.id()))).isEqualTo(1);
        assertThatThrownBy(()->application.semester(jwt(),institution,new StudentWorkspaceService.SemesterCommand(student,"future-proof",start,end.plusSeconds(1)))).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void studentAdminCannotRetireAnOngoingOffering() {
        administrator();
        assertThatThrownBy(()->application().catalog(jwt(),institution,course,new StudentWorkspaceService.CatalogCommand(student,semester,UUID.randomUUID(),"Retired","RETIRED",1))).isInstanceOf(OperationAuthorizationFailure.class);
        assertThat(jdbc.queryForObject("SELECT status FROM iam_course_offering WHERE group_id=?",String.class,bytes(course))).isEqualTo("OFFERED");
    }
    @Test void newCurrentSemesterOfferingWaitsForItsOwnProvisioningBeforeJoining() {
        administrator();StudentWorkspaceService.Course created=application().catalog(jwt(),institution,null,new StudentWorkspaceService.CatalogCommand(student,semester,UUID.randomUUID(),"New current offering","OFFERED",0));
        assertThat(created.readiness()).isEqualTo("PENDING");assertThat(created.joined()).isFalse();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_student_course WHERE group_id=?",Integer.class,bytes(created.id()))).isZero();
    }
    @Test void studyGroupDeadlineStartsOnlyAfterDurableReceiptAndRetriesCannotExtendIt() {
        StudentWorkspaceService application=application();UUID request=UUID.randomUUID();
        StudentWorkspaceService.Study first=application.createStudy(jwt(),institution,new StudentWorkspaceService.StudyCommand(student,course,request,"Private study"));
        assertThat(application.createStudy(jwt(),institution,new StudentWorkspaceService.StudyCommand(student,course,request,"Private study")).id()).isEqualTo(first.id());
        jdbc.update("UPDATE iam_study_group SET workspace_status='READY' WHERE id=?",bytes(first.id()));
        StudentWorkspaceService.Study preparing=application.deletion(jwt(),institution,student,first.id(),first.version(),false);
        assertThat(preparing.status()).isEqualTo("PREPARING");assertThat(preparing.purgeAfter()).isNull();
        org.springframework.security.oauth2.jwt.Jwt service=org.springframework.security.oauth2.jwt.Jwt.withTokenValue("synthetic-service").header("alg","RS256").subject("document-service").claim("azp","document-service").expiresAt(Instant.now().plusSeconds(60)).build();
        org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken authentication=new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken(service,java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_iam.authorization.read")));
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(authentication);
        try {
            UUID batch=UUID.randomUUID();Instant beforeReceipt=Instant.now();
            com.unidocs.auth.group.personal.PersonalGroupClosureService.Closure confirmed=closures.confirm(authentication,first.id(),preparing.version(),batch);
            assertThat(confirmed.purgeAfter()).isBetween(beforeReceipt.minusSeconds(1).plusSeconds(604800),Instant.now().plusSeconds(604801));
            assertThat(closures.confirm(authentication,first.id(),preparing.version(),batch).purgeAfter()).isEqualTo(confirmed.purgeAfter());
            assertThatThrownBy(()->closures.confirm(authentication,first.id(),preparing.version(),UUID.randomUUID())).isInstanceOf(OperationAuthorizationFailure.class);
        } finally { org.springframework.security.core.context.SecurityContextHolder.clearContext(); }
    }
    @Test void removedGroupOwnerStartsBoundedNoticePreparationWithoutImmediatePurgeOrDuplicateJobs() {
        StudentWorkspaceService.Study group=application().createStudy(jwt(),institution,new StudentWorkspaceService.StudyCommand(student,course,UUID.randomUUID(),"Orphan prevention"));
        jdbc.update("UPDATE iam_student_state SET status='REMOVED_TERMINATED',version=version+1 WHERE account_id=?",bytes(student));
        StudentInstitutionMaintenance worker=new StudentInstitutionMaintenance(jdbc,java.time.Clock.systemUTC(),outbox,transactions);
        worker.closeRemovedOwnersGroups();worker.closeRemovedOwnersGroups();
        assertThat(jdbc.queryForObject("SELECT status FROM iam_study_group WHERE id=?",String.class,bytes(group.id()))).isEqualTo("PREPARING");
        assertThat(jdbc.queryForObject("SELECT purge_after FROM iam_study_group WHERE id=?",Timestamp.class,bytes(group.id()))).isNull();
        assertThat(jdbc.queryForObject("SELECT deletion_notice_seconds FROM iam_study_group WHERE id=?",Long.class,bytes(group.id()))).isEqualTo(604800);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE aggregate_id=? AND event_type='STUDY_REMOVED_OWNER_CLOSURE'",Integer.class,bytes(institution))).isEqualTo(1);
    }
    private void administrator() {
        jdbc.update("INSERT INTO iam_student_admin(organization_id,membership_id,account_id,role_id,status) SELECT ?,?,?,role_id,'ACTIVE' FROM iam_student_role_binding WHERE responsibility='STUDENT_ADMIN'",bytes(institution),bytes(member),bytes(student));
    }
    private org.springframework.security.oauth2.jwt.Jwt jwt() { return org.springframework.security.oauth2.jwt.Jwt.withTokenValue("synthetic-student").header("alg","RS256").subject(student.toString()).claim("sid",context.session().id().toString()).expiresAt(Instant.now().plusSeconds(300)).build(); }
    @SuppressWarnings("unchecked")
    private StudentWorkspaceService application() {
        SessionAccess access=mock(SessionAccess.class);
        doAnswer(call->((java.util.function.Function<SessionAccess.Context,Object>)call.getArgument(2)).apply(context)).when(access).execute(eq(context.session().id()),eq(student),any());
        return new StudentWorkspaceService(jdbc,access,authority,outbox,validator,java.time.Clock.systemUTC());
    }
    private UUID account(String type,UUID organization,UUID actorUser) {
        jdbc.update("INSERT IGNORE INTO users(id,display_name,status,created_at,updated_at) VALUES(?,'Synthetic student fixture','ACTIVE',?,?)",bytes(actorUser),time(now),time(now));
        UUID id=UUID.randomUUID();jdbc.update("INSERT INTO user_account(id,user_id,organization_id,type,display_name,status,created_at,updated_at) VALUES(?,?,?,?,'Synthetic student fixture','ACTIVE',?,?)",bytes(id),bytes(actorUser),organization==null?null:bytes(organization),type,time(now),time(now));return id;
    }
    private void denied(String operation,UUID group) { assertThatThrownBy(()->authority.require(context,student,institution,group,"document-service",operation)).isInstanceOf(OperationAuthorizationFailure.class); }
    private static Timestamp time(Instant value) { return Timestamp.from(value); }
}
