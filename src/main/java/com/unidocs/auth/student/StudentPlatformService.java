package com.unidocs.auth.student;

import java.time.Clock;
import java.util.List;
import java.util.UUID;
import com.unidocs.auth.account.lifecycle.LifecycleRepository;
import com.unidocs.auth.authorization.controlplane.DeveloperCatalogService;
import com.unidocs.auth.authorization.controlplane.DeveloperGate;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.persistence.SessionRepository;
import jakarta.validation.Validator;
import jakarta.validation.constraints.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static com.unidocs.auth.group.persistence.GroupRuleRepository.uuid;
import static com.unidocs.auth.student.StudentWorkspaceService.time;

@Service
@Transactional(propagation=Propagation.NEVER)
public class StudentPlatformService {
    public record Appointment(@NotNull UUID targetAccountId,boolean active,@PositiveOrZero long expectedVersion) { }
    public record ProofCommand(@NotNull UUID id,@NotNull UUID targetAccountId,UUID reportId,
            @NotNull @Pattern(regexp="POLICY_VIOLATION|INTRUDER|STUDENTSHIP_TERMINATION") String kind,
            @NotBlank @Size(max=512) String evidenceReference,boolean verifiedWithInstitution) {
        @Override public String toString() { return "StudentProofCommand[REDACTED]"; }
    }
    public record Decision(@NotNull UUID requestId,@NotNull UUID targetAccountId,@NotNull UUID proofId,
            @NotNull @Pattern(regexp="RESTRICT|REVERSE|REMOVE_INTRUDER|REMOVE_TERMINATED") String action,
            @Positive long expectedVersion) { }
    public record Result(UUID targetAccountId,String status,long version) { }
    private final JdbcTemplate jdbc;
    private final DeveloperGate gate;
    private final StudentWorkspaceService changes;
    private final LifecycleRepository lifecycle;
    private final SessionRepository sessions;
    private final Validator validator;
    private final OutboxRepository outbox;
    public StudentPlatformService(JdbcTemplate jdbc,DeveloperGate gate,StudentWorkspaceService changes,
            LifecycleRepository lifecycle,SessionRepository sessions,Validator validator,OutboxRepository outbox) {
        this.jdbc=jdbc;this.gate=gate;this.changes=changes;this.lifecycle=lifecycle;this.sessions=sessions;this.validator=validator;this.outbox=outbox;
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Result appoint(Jwt jwt,DeveloperCatalogService.Proof proof,UUID organization,Appointment command) {
        validate(proof,command);
        return gate.executeForGroups(jwt,proof.accountId(),proof.password(),proof.secondFactor(),"student-appoint:"+organization+":"+command.targetAccountId()+":"+command.expectedVersion()+":"+command.active(),groups(command.targetAccountId()),c->{
            changes.fence(organization);
            List<UUID> members=jdbc.query("""
                    SELECT m.id FROM organization_membership m JOIN user_account a ON a.id=m.account_id
                    JOIN users u ON u.id=a.user_id AND u.status='ACTIVE'
                    WHERE m.organization_id=? AND a.organization_id=m.organization_id AND a.id=? AND a.type='UNIVERSITY'
                    AND a.status='ACTIVE' AND m.status='ACTIVE'
                    AND EXISTS(SELECT 1 FROM user_contact e WHERE e.user_id=a.user_id AND e.type='EMAIL' AND e.verified=TRUE)
                    AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=m.organization_id AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED','PURGED')) FOR UPDATE
                    """,(row,index)->uuid(row.getBytes(1)),bytes(organization),bytes(command.targetAccountId()));
            if(members.size()!=1) throw StudentAuthorization.denied();UUID member=members.getFirst();
            List<Long> old=jdbc.query("SELECT version FROM iam_student_admin WHERE organization_id=? AND membership_id=? FOR UPDATE",(row,index)->row.getLong(1),bytes(organization),bytes(member));
            long version=old.isEmpty()?0:old.getFirst();if(version!=command.expectedVersion()) throw StudentWorkspaceService.conflict();
            List<UUID> role=jdbc.query("SELECT b.role_id FROM iam_student_role_binding b JOIN iam_role r ON r.id=b.role_id AND r.status='ACTIVE' WHERE b.responsibility='STUDENT_ADMIN' AND b.status='ACTIVE'",(row,index)->uuid(row.getBytes(1)));
            if(role.size()!=1) throw StudentAuthorization.denied();
            jdbc.update("INSERT INTO iam_student_admin(organization_id,membership_id,account_id,role_id,status) VALUES(?,?,?,?,?) ON DUPLICATE KEY UPDATE status=VALUES(status),role_id=VALUES(role_id),version=version+1",bytes(organization),bytes(member),bytes(command.targetAccountId()),bytes(role.getFirst()),command.active()?"ACTIVE":"REVOKED");
            jdbc.update("UPDATE iam_student_staff_reconciliation SET status='RECONCILED' WHERE organization_id=? AND membership_id=?",bytes(organization),bytes(member));
            changes.changed(c,organization,proof.accountId(),member,"STUDENT_ADMIN_APPOINTMENT_CHANGED",command.targetAccountId());
            return new Result(command.targetAccountId(),command.active()?"ACTIVE":"REVOKED",version+1);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public UUID verifyProof(Jwt jwt,DeveloperCatalogService.Proof proof,UUID organization,ProofCommand command) {
        validate(proof,command);StudentWorkspaceService.evidence(command.evidenceReference());
        if(!command.verifiedWithInstitution()) throw StudentWorkspaceService.bad();
        return gate.executeForGroups(jwt,proof.accountId(),proof.password(),proof.secondFactor(),"student-proof:"+command.id(),groups(command.targetAccountId()),c->{
            changes.fence(organization);
            lifecycle.memberForAccount(organization,command.targetAccountId()).orElseThrow(StudentAuthorization::denied);
            if(!command.kind().equals("STUDENTSHIP_TERMINATION")) escalated(organization,command.targetAccountId(),command.reportId());
            List<Proof> old=jdbc.query("SELECT target_account_id,report_id,proof_kind,evidence_reference FROM iam_student_enforcement_proof WHERE id=? AND organization_id=? FOR UPDATE",
                    (row,index)->new Proof(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getString(3),row.getString(4)),bytes(command.id()),bytes(organization));
            if(!old.isEmpty()) {
                Proof previous=old.getFirst();if(!previous.target().equals(command.targetAccountId())||!java.util.Objects.equals(previous.report(),command.reportId())||!previous.kind().equals(command.kind())||!previous.reference().equals(command.evidenceReference())) throw StudentWorkspaceService.conflict();return command.id();
            }
            jdbc.update("INSERT INTO iam_student_enforcement_proof VALUES(?,?,?,?,?,?,?,?)",bytes(command.id()),bytes(organization),bytes(command.targetAccountId()),StudentWorkspaceService.nullable(command.reportId()),command.kind(),command.evidenceReference(),bytes(proof.accountId()),time(c.now()));
            changes.changed(c,organization,proof.accountId(),command.id(),"STUDENT_PLATFORM_PROOF_VERIFIED",command.targetAccountId());return command.id();
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Result enforce(Jwt jwt,DeveloperCatalogService.Proof proof,UUID organization,Decision command) {
        validate(proof,command);
        List<UUID> groups=groups(command.targetAccountId());
        return gate.executeForGroups(jwt,proof.accountId(),proof.password(),proof.secondFactor(),"student-decision:"+command.requestId(),groups,c->{
            changes.fence(organization);
            List<Previous> previous=jdbc.query("SELECT target_account_id,proof_id,action_key,expected_version,result_status,result_version,actor_account_id FROM iam_student_decision WHERE organization_id=? AND request_id=? FOR UPDATE",
                    (row,index)->new Previous(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getString(3),row.getLong(4),row.getString(5),row.getLong(6),uuid(row.getBytes(7))),bytes(organization),bytes(command.requestId()));
            if(!previous.isEmpty()) {
                Previous old=previous.getFirst();if(!old.target().equals(command.targetAccountId())||!old.proof().equals(command.proofId())||!old.action().equals(command.action())||old.expected()!=command.expectedVersion()||!old.actor().equals(proof.accountId())) throw StudentWorkspaceService.conflict();return new Result(old.target(),old.status(),old.version());
            }
            LifecycleRepository.Member member=lifecycle.memberForAccount(organization,command.targetAccountId()).orElseThrow(StudentAuthorization::denied);
            if(member.userId().equals(c.owner().userId())) throw StudentAuthorization.denied();
            Proof evidence=jdbc.query("SELECT target_account_id,report_id,proof_kind,evidence_reference FROM iam_student_enforcement_proof WHERE id=? AND organization_id=? FOR SHARE",(row,index)->new Proof(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getString(3),row.getString(4)),bytes(command.proofId()),bytes(organization)).stream().findFirst().orElseThrow(StudentAuthorization::denied);
            if(!evidence.target().equals(command.targetAccountId())) throw StudentAuthorization.denied();
            boolean escalated=false;if(evidence.report()!=null) { escalated(organization,command.targetAccountId(),evidence.report());escalated=true; }
            if(!StudentRules.validDecision(command.action(),evidence.kind(),escalated)) throw StudentAuthorization.denied();
            State current=jdbc.query("SELECT status,version FROM iam_student_state WHERE organization_id=? AND membership_id=? FOR UPDATE",(row,index)->new State(row.getString(1),row.getLong(2)),bytes(organization),bytes(member.id())).stream().findFirst().orElseThrow(StudentAuthorization::denied);
            if(current.version()!=command.expectedVersion()||!StudentRules.admitted(current.status())) throw StudentWorkspaceService.conflict();
            String state=switch(command.action()) { case "RESTRICT" -> "COLLABORATION_RESTRICTED";case "REVERSE" -> "ACTIVE";case "REMOVE_INTRUDER" -> "REMOVED_INTRUDER";case "REMOVE_TERMINATED" -> "REMOVED_TERMINATED";default -> throw StudentWorkspaceService.bad(); };
            if(state.equals(current.status())) throw StudentWorkspaceService.conflict();
            if(command.action().equals("REVERSE")&&!current.status().equals("COLLABORATION_RESTRICTED")) throw StudentWorkspaceService.conflict();
            jdbc.update("UPDATE iam_student_state SET status=?,version=version+1 WHERE organization_id=? AND membership_id=?",state,bytes(organization),bytes(member.id()));
            if(state.startsWith("REMOVED_")) {
                lifecycle.restrict(organization,member,proof.accountId(),"REMOVED",c.now().plusSeconds(604800),c.now());
                jdbc.update("UPDATE iam_study_member m JOIN iam_study_group g ON g.id=m.group_id SET m.status='REVOKED',m.version=m.version+1 WHERE g.organization_id=? AND m.account_id=? AND m.status='ACTIVE'",bytes(organization),bytes(command.targetAccountId()));
                jdbc.update("UPDATE iam_study_invitation i JOIN iam_study_group g ON g.id=i.group_id SET i.status='REVOKED',i.version=i.version+1 WHERE g.organization_id=? AND i.recipient_account_id=? AND i.status='PENDING'",bytes(organization),bytes(command.targetAccountId()));
                jdbc.update("UPDATE iam_student_admin SET status='REVOKED',version=version+1 WHERE organization_id=? AND account_id=?",bytes(organization),bytes(command.targetAccountId()));
                lifecycle.fallback(member.userId(),c.now());sessions.reconcileGroup(member.groupId(),c.now());
            }
            // Keep existing membership and read relationships during collaboration restriction/reversal.
            changes.changed(c,organization,proof.accountId(),member.id(),"STUDENT_ENFORCEMENT_CHANGED",command.targetAccountId());
            LifecycleRepository.Account account=lifecycle.account(command.targetAccountId(),false).orElseThrow(StudentAuthorization::denied);
            UUID notice=lifecycle.notice(account,"STUDENT_ENFORCEMENT_CHANGED","Institutional access changed by a platform decision.",state.startsWith("REMOVED_")?c.now().plusSeconds(604800):null,c.now());
            outbox.lifecycle("SECURITY_NOTICE",notice,1,"SECURITY_NOTICE_CREATED",account.id(),organization,null,c.now());
            jdbc.update("INSERT INTO iam_student_decision VALUES(?,?,?,?,?,?,?,?,?)",bytes(organization),bytes(command.requestId()),bytes(command.targetAccountId()),bytes(command.proofId()),command.action(),command.expectedVersion(),state,current.version()+1,bytes(proof.accountId()));
            return new Result(command.targetAccountId(),state,current.version()+1);
        });
    }
    private void escalated(UUID organization,UUID target,UUID report) {
        if(report==null||!Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_student_report WHERE id=? AND organization_id=? AND target_account_id=? AND status='ESCALATED')",Boolean.class,StudentWorkspaceService.nullable(report),bytes(organization),bytes(target)))) throw StudentAuthorization.denied();
    }
    private List<UUID> groups(UUID account) {
        List<UUID> groups=jdbc.query("SELECT account_group_id FROM account_group_member WHERE account_id=? AND status='LINKED'",(row,index)->uuid(row.getBytes(1)),bytes(account));
        if(groups.size()!=1) throw StudentAuthorization.denied();return groups;
    }
    private void validate(DeveloperCatalogService.Proof proof,Object command) { if(proof==null||proof.accountId()==null||command==null||!validator.validate(command).isEmpty()) throw StudentWorkspaceService.bad(); }
    private record Proof(UUID target,UUID report,String kind,String reference) { @Override public String toString() { return "StudentProof[REDACTED]"; } }
    private record State(String status,long version) { }
    private record Previous(UUID target,UUID proof,String action,long expected,String status,long version,UUID actor) { }
}
