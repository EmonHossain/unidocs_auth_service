package com.unidocs.auth.student;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import com.unidocs.auth.authorization.api.OperationAuthorizationResponse;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.authorization.domain.OperationAuthorityEvidence;
import com.unidocs.auth.authorization.domain.OperationAuthorityPolicy;
import com.unidocs.auth.authorization.domain.OperationPolicySnapshot;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static com.unidocs.auth.group.persistence.GroupRuleRepository.uuid;

@Service
@Transactional(propagation=Propagation.MANDATORY)
public class StudentAuthorization {
    public record Student(UUID membershipId,UUID userId,String state,long version) { }
    public record GroupSnapshot(UUID id,String role,long version) { }
    public GroupSnapshot groupSnapshot(UUID organization,UUID group,UUID account) {
        List<GroupSnapshot> study=jdbc.query("SELECT m.id,IF(g.owner_account_id=m.account_id,'OWNER','MEMBER'),m.version FROM iam_study_member m JOIN iam_study_group g ON g.id=m.group_id WHERE g.organization_id=? AND g.id=? AND m.account_id=? AND m.status='ACTIVE'",
                (row,index)->new GroupSnapshot(uuid(row.getBytes(1)),row.getString(2),row.getLong(3)),bytes(organization),bytes(group),bytes(account));
        if(!study.isEmpty()) return study.getFirst();
        return jdbc.query("SELECT id,version FROM iam_student_course WHERE organization_id=? AND group_id=? AND account_id=?",(row,index)->new GroupSnapshot(uuid(row.getBytes(1)),"STUDENT",row.getLong(2)),bytes(organization),bytes(group),bytes(account)).stream().findFirst().orElseThrow(StudentAuthorization::denied);
    }
    private final JdbcTemplate jdbc;
    private final SessionRepository sessions;
    private final OrganizationRepository organizations;
    private final OperationPolicyCatalogRepository policies;
    private final Clock clock;
    public StudentAuthorization(JdbcTemplate jdbc,SessionRepository sessions,OrganizationRepository organizations,
            OperationPolicyCatalogRepository policies,Clock clock) {
        this.jdbc=jdbc;this.sessions=sessions;this.organizations=organizations;this.policies=policies;this.clock=clock;
    }
    public boolean institutional(UUID organization) { return organizations.university(organization); }
    @Transactional(propagation=Propagation.SUPPORTS,readOnly=true)
    public UUID institution(UUID account) {
        return jdbc.query("SELECT organization_id FROM user_account WHERE id=? AND type='UNIVERSITY' AND status='ACTIVE'",
                (row,index)->uuid(row.getBytes(1)),bytes(account)).stream().findFirst().orElse(null);
    }
    public Student student(UUID organization,UUID account) {
        List<Student> students=jdbc.query("""
                SELECT m.id,a.user_id,s.status,s.version FROM organization_membership m
                JOIN organization o ON o.id=m.organization_id AND o.type='UNIVERSITY' AND o.status='ACTIVE'
                JOIN user_account a ON a.id=m.account_id AND a.organization_id=o.id AND a.type='UNIVERSITY' AND a.status='ACTIVE'
                JOIN users u ON u.id=a.user_id AND u.status='ACTIVE'
                JOIN iam_student_state s ON s.organization_id=o.id AND s.membership_id=m.id AND s.account_id=a.id
                WHERE o.id=? AND a.id=? AND m.status='ACTIVE'
                AND EXISTS(SELECT 1 FROM student_admission d WHERE d.organization_id=o.id AND d.membership_id=m.id AND d.student_account_id=a.id AND d.status='APPROVED')
                AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=o.id AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED','PURGED'))
                FOR SHARE
                """,(row,index)->new Student(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getString(3),row.getLong(4)),bytes(organization),bytes(account));
        if(students.size()!=1||!StudentRules.admitted(students.getFirst().state())) throw denied();
        return students.getFirst();
    }
    public void course(UUID organization,UUID course,UUID account,String operation) {
        Student student=student(organization,account);
        List<Course> courses=jdbc.query("""
                SELECT s.starts_at,s.ends_at,w.status FROM iam_student_course c
                JOIN iam_course_offering o ON o.group_id=c.group_id AND o.organization_id=c.organization_id
                JOIN academic_semester s ON s.id=o.semester_id AND s.organization_id=o.organization_id
                JOIN iam_semester_workspace w ON w.semester_id=s.id
                JOIN iam_group g ON g.id=o.group_id AND g.status='ACTIVE'
                WHERE c.organization_id=? AND c.group_id=? AND c.membership_id=? AND c.account_id=? AND o.status IN('OFFERED','FINALIZED','RETIRED') AND o.workspace_status='READY'
                FOR SHARE
                """,(row,index)->new Course(row.getTimestamp(1).toInstant(),row.getTimestamp(2).toInstant(),row.getString(3)),
                bytes(organization),bytes(course),bytes(student.membershipId()),bytes(account));
        Instant now=clock.instant();
        if(courses.size()!=1||!"READY".equals(courses.getFirst().ready())||now.isBefore(courses.getFirst().start())
                ||!now.isBefore(courses.getFirst().end())&&!StudentRules.RECOVERY.contains(operation)) throw denied();
    }
    public OperationAuthorizationResponse require(SessionAccess.Context context,UUID account,UUID organization,
            UUID group,String service,String operation) {
        Instant started=clock.instant();
        SessionAccountGrant grant=sessions.liveGrant(context.session(),account,clock.instant()).orElseThrow(StudentAuthorization::denied);
        Long revision=jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR SHARE",Long.class);
        if(revision==null||!organization.equals(institution(account))) throw denied();
        List<UUID> identities=jdbc.query("SELECT id FROM user_account WHERE id=? AND user_id=? AND status='ACTIVE' FOR SHARE",
                (row,index)->uuid(row.getBytes(1)),bytes(account),bytes(context.owner().userId()));
        if(identities.size()!=1) throw denied();
        OrganizationRepository.Visibility member=organizations.visibility(account,grant.authMethod(),organization).orElseThrow(StudentAuthorization::denied);
        OperationPolicySnapshot policy=policies.findCurrent(service,operation,"STUDENT").orElseThrow(StudentAuthorization::denied);
        Set<UUID> local=new HashSet<>();
        boolean admin=admin(organization,member.membershipId());
        if(admin) {
            if(!StudentRules.ADMIN_OPERATIONS.contains(operation)||!Set.of("LOGIN","PASSWORD").contains(grant.authMethod())) throw denied();
            local.addAll(jdbc.query("SELECT ra.authority_id FROM iam_student_admin a JOIN iam_student_role_binding b ON b.responsibility='STUDENT_ADMIN' AND b.status='ACTIVE' JOIN iam_role r ON r.id=b.role_id AND r.status='ACTIVE' JOIN iam_role_authority ra ON ra.role_id=r.id WHERE a.organization_id=? AND a.membership_id=? AND a.status='ACTIVE'",
                    (row,index)->uuid(row.getBytes(1)),bytes(organization),bytes(member.membershipId())));
        } else {
            Student student=student(organization,account);
            if(!StudentRules.permits(student.state(),operation)) throw denied();
            local.addAll(role("STUDENT"));
            if(group!=null) {
                List<Study> study=jdbc.query("SELECT s.course_id,s.owner_account_id,s.status,s.purge_after FROM iam_study_group s JOIN iam_study_member m ON m.group_id=s.id AND m.account_id=? AND m.status='ACTIVE' WHERE s.id=? AND s.organization_id=? AND s.workspace_status='READY' FOR SHARE",
                        (row,index)->new Study(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getString(3),row.getTimestamp(4)==null?null:row.getTimestamp(4).toInstant()),bytes(account),bytes(group),bytes(organization));
                if(!study.isEmpty()) {
                    Study current=study.getFirst();course(organization,current.course(),account,operation);
                    if(!StudentRules.groupAvailable(current.status(),current.deadline(),operation,clock.instant())) throw denied();
                    local.addAll(role(current.owner().equals(account)?"STUDY_OWNER":"STUDY_MEMBER"));
                } else course(organization,group,account,operation);
            } else if(operation.startsWith("group.")&&!Set.of("group.read","group.invitation.accept","group.invitation.decline").contains(operation)) throw denied();
        }
        Instant now=clock.instant();
        boolean restricted=Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_operation_restriction WHERE operation_id=? AND category_key='STUDENT' AND (account_id IS NULL OR account_id=?) AND status='ACTIVE' AND valid_from<=? AND (valid_until IS NULL OR valid_until>?))",
                Boolean.class,bytes(policy.operationId()),bytes(account),Timestamp.from(now),Timestamp.from(now)));
        if(!new OperationAuthorityPolicy(policy.policy().requiredAuthorityIds(),policy.policy().matchMode(),true)
                .matches(new OperationAuthorityEvidence(policy.categoryAuthorityIds(),local,true,restricted))) throw denied();
        // Recheck timed eligibility after SQL waits. Policy/state writers serialize at the global fence.
        Instant checked=clock.instant();
        if(!context.session().activeAt(checked)||!grant.activeAt(checked,grant.credentialVersion())) throw denied();
        if(group!=null&&!admin) {
            UUID course=jdbc.query("SELECT course_id FROM iam_study_group WHERE id=? AND organization_id=?",(row,index)->uuid(row.getBytes(1)),bytes(group),bytes(organization)).stream().findFirst().orElse(group);
            course(organization,course,account,operation);
            List<Study> state=jdbc.query("SELECT course_id,owner_account_id,status,purge_after FROM iam_study_group WHERE id=? AND organization_id=?",(row,index)->new Study(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getString(3),row.getTimestamp(4)==null?null:row.getTimestamp(4).toInstant()),bytes(group),bytes(organization));
            if(!state.isEmpty()&&!StudentRules.groupAvailable(state.getFirst().status(),state.getFirst().deadline(),operation,clock.instant())) throw denied();
        }
        Map<UUID,String> keys=new HashMap<>();
        jdbc.query("SELECT a.id,a.authority_key FROM iam_policy_authority p JOIN iam_authority a ON a.id=p.authority_id WHERE p.policy_id=?",
                row->{keys.put(uuid(row.getBytes(1)),row.getString(2));},bytes(policy.policyId()));
        Set<String> required=new HashSet<>();Set<String> eligible=new HashSet<>();
        for(UUID authority:policy.policy().requiredAuthorityIds()) {
            if(keys.get(authority)==null) throw denied();required.add(keys.get(authority));
            if(local.contains(authority)&&policy.categoryAuthorityIds().contains(authority)) eligible.add(keys.get(authority));
        }
        checked=checkedAt(account,organization,group,policy.operationId(),started);
        if(!context.session().activeAt(checked)||!grant.activeAt(checked,grant.credentialVersion())) throw denied();
        sessions.touch(context.session(),grant,checked);
        return new OperationAuthorizationResponse(account,context.owner().userId(),context.session().id(),policy.operationId(),operation,"STUDENT",policy.policyId(),policy.policy().matchMode(),required,eligible,
                policy.operationVersion(),policy.policyVersion(),policy.categoryBindingVersion(),policy.categoryRoleVersion(),revision,policy.authorityVersions(),checked,checked,"ALLOWED");
    }
    public boolean admin(UUID organization,UUID member) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_student_admin a WHERE a.organization_id=? AND a.membership_id=? AND a.status='ACTIVE')",Boolean.class,bytes(organization),bytes(member)));
    }
    public UUID recipient(UUID organization,UUID group,UUID account,String mode) {
        Instant started=clock.instant();
        Student student=student(organization,account);
        if(!StudentRules.permits(student.state(),"group.invitation.accept")) throw denied();
        if(group!=null) {
            UUID course=jdbc.query("SELECT course_id FROM iam_study_group WHERE id=? AND organization_id=?",(row,index)->uuid(row.getBytes(1)),bytes(group),bytes(organization)).stream().findFirst().orElse(group);
            course(organization,course,account,"group.invitation.accept");
        }
        if(!Set.of("VIEW","EDIT").contains(mode)) throw denied();
        if(admin(organization,student.membershipId())) throw denied();
        Set<UUID> local=role("STUDENT");
        for(String operation:mode.equals("EDIT")?List.of("file.read","file.edit","file.collaborative.edit"):List.of("file.read")) {
            OperationPolicySnapshot policy=policies.findCurrent("document-service",operation,"STUDENT").orElseThrow(StudentAuthorization::denied);
            Instant now=clock.instant();
            boolean restricted=Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_operation_restriction WHERE operation_id=? AND category_key='STUDENT' AND (account_id IS NULL OR account_id=?) AND status='ACTIVE' AND valid_from<=? AND (valid_until IS NULL OR valid_until>?))",Boolean.class,bytes(policy.operationId()),bytes(account),Timestamp.from(now),Timestamp.from(now)));
            if(!new OperationAuthorityPolicy(policy.policy().requiredAuthorityIds(),policy.policy().matchMode(),true).matches(new OperationAuthorityEvidence(policy.categoryAuthorityIds(),local,true,restricted))) throw denied();
            checkedAt(account,organization,group,policy.operationId(),started);
        }
        return student.userId();
    }
    private Set<UUID> role(String responsibility) {
        return new HashSet<>(jdbc.query("SELECT ra.authority_id FROM iam_student_role_binding b JOIN iam_role r ON r.id=b.role_id AND r.status='ACTIVE' JOIN iam_role_authority ra ON ra.role_id=r.id WHERE b.responsibility=? AND b.status='ACTIVE'",
                (row,index)->uuid(row.getBytes(1)),responsibility));
    }
    private Instant checkedAt(UUID account,UUID organization,UUID group,UUID operation,Instant started) {
        org.springframework.jdbc.core.namedparam.MapSqlParameterSource parameters=new org.springframework.jdbc.core.namedparam.MapSqlParameterSource()
                .addValue("account",bytes(account)).addValue("organization",bytes(organization)).addValue("group",StudentWorkspaceService.nullable(group))
                .addValue("operation",bytes(operation)).addValue("started",Timestamp.from(started));
        Timestamp boundary=new org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate(jdbc).queryForObject("""
                SELECT MIN(boundary) FROM (
                 SELECT valid_from boundary FROM iam_operation_restriction WHERE operation_id=:operation AND category_key='STUDENT'
                   AND (account_id IS NULL OR account_id=:account) AND status='ACTIVE' AND valid_from>:started
                 UNION ALL SELECT valid_until FROM iam_operation_restriction WHERE operation_id=:operation AND category_key='STUDENT'
                   AND (account_id IS NULL OR account_id=:account) AND status='ACTIVE' AND valid_until>:started
                 UNION ALL SELECT s.starts_at FROM academic_semester s JOIN iam_course_offering o ON o.semester_id=s.id
                   WHERE o.organization_id=:organization AND o.group_id=COALESCE((SELECT course_id FROM iam_study_group WHERE id=:group AND organization_id=:organization),:group) AND s.starts_at>:started
                 UNION ALL SELECT s.ends_at FROM academic_semester s JOIN iam_course_offering o ON o.semester_id=s.id
                   WHERE o.organization_id=:organization AND o.group_id=COALESCE((SELECT course_id FROM iam_study_group WHERE id=:group AND organization_id=:organization),:group) AND s.ends_at>:started
                 UNION ALL SELECT purge_after FROM iam_study_group WHERE id=:group AND organization_id=:organization AND purge_after>:started
                ) transitions
                """,parameters,Timestamp.class);
        Instant checked=clock.instant();if(checked.isBefore(started)||boundary!=null&&!checked.isBefore(boundary.toInstant())) throw denied();return checked;
    }
    public static OperationAuthorizationFailure denied() { return new OperationAuthorizationFailure(HttpStatus.FORBIDDEN,"STUDENT_CAPABILITY_DENIED"); }
    private record Course(Instant start,Instant end,String ready) { }
    private record Study(UUID course,UUID owner,String status,Instant deadline) { }
}
