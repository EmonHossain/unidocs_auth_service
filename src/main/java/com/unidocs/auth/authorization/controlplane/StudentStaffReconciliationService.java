package com.unidocs.auth.authorization.controlplane;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import com.unidocs.auth.account.domain.AccountGroupMember;
import com.unidocs.auth.account.domain.UserAccount;
import com.unidocs.auth.authentication.domain.LoginIdentity;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import jakarta.persistence.EntityManager;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static com.unidocs.auth.group.persistence.GroupRuleRepository.uuid;

/** Converts a legacy staff institution anchor without granting Student Admin or student content rights. */
@Service
public class StudentStaffReconciliationService {
    public record Command(UUID sourceAccountId,UUID targetAccountId,String newAccountPassword,String displayName,long expectedVersion) {
        @Override public String toString() { return "StudentStaffReconciliation[REDACTED]"; }
    }
    public record Result(UUID accountId,UUID membershipId,long organizationVersion) { }
    private record Actor(Instant now,UUID operatorId,UUID productAccountId,UUID sessionId,SessionAccess.Context legacy) { }
    private final JdbcTemplate jdbc;
    private final DeveloperGate gate;
    private final DeveloperOperatorGate operatorGate;
    private final boolean operatorMode;
    private final EntityManager entities;
    private final PasswordEncoder passwords;
    private final OutboxRepository outbox;
    public StudentStaffReconciliationService(JdbcTemplate jdbc,DeveloperGate gate,EntityManager entities,PasswordEncoder passwords,OutboxRepository outbox) {
        this(jdbc,gate,(DeveloperOperatorGate)null,false,entities,passwords,outbox);
    }
    @org.springframework.beans.factory.annotation.Autowired
    public StudentStaffReconciliationService(JdbcTemplate jdbc,DeveloperGate gate,
            org.springframework.beans.factory.ObjectProvider<DeveloperOperatorGate> operatorGates,
            @org.springframework.beans.factory.annotation.Value("${auth.developer.operator.enabled:false}") boolean operatorMode,
            EntityManager entities,PasswordEncoder passwords,OutboxRepository outbox) {
        this(jdbc,gate,operatorGates.getIfAvailable(),operatorMode,entities,passwords,outbox);
    }
    private StudentStaffReconciliationService(JdbcTemplate jdbc,DeveloperGate gate,DeveloperOperatorGate operatorGate,
            boolean operatorMode,EntityManager entities,PasswordEncoder passwords,OutboxRepository outbox) {
        this.jdbc=jdbc;this.gate=gate;this.operatorGate=operatorGate;this.operatorMode=operatorMode;
        this.entities=entities;this.passwords=passwords;this.outbox=outbox;
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Result reconcile(Jwt jwt,DeveloperCatalogService.Proof proof,UUID organization,Command command) {
        if(proof==null||command==null||command.sourceAccountId()==null||command.expectedVersion()<1||command.sourceAccountId().equals(command.targetAccountId())) throw bad();
        if(operatorMode && (proof.accountId()!=null || proof.reason()==null || proof.reason().isBlank()
                || proof.reason().length()>512))throw bad();
        if(command.targetAccountId()==null&&(command.newAccountPassword()==null||command.newAccountPassword().length()<12||command.newAccountPassword().length()>128
                ||command.displayName()==null||command.displayName().isBlank()||command.displayName().strip().length()>100||command.displayName().codePoints().anyMatch(Character::isISOControl))) throw bad();
        if(command.targetAccountId()!=null&&(command.newAccountPassword()!=null||command.displayName()!=null)) throw bad();
        List<UUID> groups=jdbc.query("SELECT account_group_id FROM account_group_member WHERE account_id=? AND status='LINKED'",(row,index)->uuid(row.getBytes(1)),bytes(command.sourceAccountId()));
        if(groups.size()!=1) throw denied();String hash=command.targetAccountId()==null?passwords.encode(command.newAccountPassword()):null;
        Function<Actor,Result> operation=c->{
            List<UUID> lockedGroup=jdbc.query("SELECT id FROM account_group WHERE id=? AND status='ACTIVE' FOR UPDATE",
                    (row,index)->uuid(row.getBytes(1)),bytes(groups.getFirst()));
            if(lockedGroup.size()!=1)throw denied();
            jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE",Long.class);
            Long version=jdbc.query("SELECT authorization_version FROM organization WHERE id=? AND type='UNIVERSITY' AND status='ACTIVE' FOR UPDATE",(row,index)->row.getLong(1),bytes(organization)).stream().findFirst().orElseThrow(StudentStaffReconciliationService::denied);
            List<Result> old=jdbc.query("SELECT target_account_id,target_membership_id FROM iam_student_staff_reconciliation r JOIN organization_membership m ON m.id=r.membership_id WHERE r.organization_id=? AND m.account_id=? AND r.status='RECONCILED'",(row,index)->new Result(uuid(row.getBytes(1)),uuid(row.getBytes(2)),version),bytes(organization),bytes(command.sourceAccountId()));
            if(!old.isEmpty()) { if(command.targetAccountId()!=null&&!command.targetAccountId().equals(old.getFirst().accountId())) throw conflict();return old.getFirst(); }
            if(version!=command.expectedVersion()) throw conflict();
            Source source=jdbc.query("""
                    SELECT a.user_id,m.id FROM user_account a JOIN organization_membership m ON m.account_id=a.id
                    JOIN iam_student_staff_reconciliation r ON r.organization_id=m.organization_id AND r.membership_id=m.id AND r.status='PENDING'
                    WHERE a.id=? AND a.type='PERSONAL' AND a.status='ACTIVE' AND m.organization_id=? AND m.status='ACTIVE'
                    AND EXISTS(SELECT 1 FROM user_contact e WHERE e.user_id=a.user_id AND e.type='EMAIL' AND e.verified=TRUE)
                    AND NOT EXISTS(SELECT 1 FROM organization_account_restriction x WHERE x.organization_id=m.organization_id AND x.user_id=a.user_id AND x.status IN('REMOVED','BLACKLISTED','PURGED')) FOR UPDATE
                    """,(row,index)->new Source(uuid(row.getBytes(1)),uuid(row.getBytes(2))),bytes(command.sourceAccountId()),bytes(organization)).stream().findFirst().orElseThrow(StudentStaffReconciliationService::denied);
            UUID target=command.targetAccountId();
            if(target==null) {
                UserAccount account=new UserAccount(UUID.randomUUID(),source.user(),organization,UserAccount.Type.UNIVERSITY,command.displayName().strip(),c.now());
                entities.persist(account);entities.flush();target=account.id();
                entities.persist(new LoginIdentity(UUID.randomUUID(),target,LoginIdentity.Type.ACCOUNT_ID,target.toString(),hash,c.now()));entities.flush();
                entities.persist(new AccountGroupMember(account,groups.getFirst(),source.user(),command.sourceAccountId(),c.now()));entities.flush();
            } else {
                List<UUID> targets=jdbc.query("SELECT a.id FROM user_account a JOIN account_group_member g ON g.account_id=a.id AND g.status='LINKED' WHERE a.id=? AND a.user_id=? AND a.type='UNIVERSITY' AND a.organization_id=? AND a.status='ACTIVE' AND g.account_group_id=? FOR UPDATE",(row,index)->uuid(row.getBytes(1)),bytes(target),bytes(source.user()),bytes(organization),bytes(groups.getFirst()));
                if(targets.size()!=1) throw denied();
            }
            UUID member;
            List<Member> existing=jdbc.query("SELECT id,status FROM organization_membership WHERE organization_id=? AND account_id=? FOR UPDATE",(row,index)->new Member(uuid(row.getBytes(1)),row.getString(2)),bytes(organization),bytes(target));
            if(existing.isEmpty()) {
                member=UUID.randomUUID();jdbc.update("INSERT INTO organization_membership(id,organization_id,account_id,role,status,version,joined_at,created_at,updated_at) VALUES(?,?,?,'MEMBER','ACTIVE',1,?,?,?)",bytes(member),bytes(organization),bytes(target),Timestamp.from(c.now()),Timestamp.from(c.now()),Timestamp.from(c.now()));
            } else { if(!existing.getFirst().status().equals("ACTIVE")) throw denied();member=existing.getFirst().id(); }
            // Preserve account-scoped platform blocks; do not copy legacy administrator/course grants.
            jdbc.update("INSERT INTO iam_operation_restriction(id,operation_id,category_key,account_id,status,version,valid_from,valid_until) SELECT UUID_TO_BIN(UUID()),operation_id,'STUDENT',?,'ACTIVE',1,valid_from,valid_until FROM iam_operation_restriction WHERE account_id=? AND category_key='STUDENT' AND status='ACTIVE'",bytes(target),bytes(command.sourceAccountId()));
            jdbc.update("UPDATE organization_membership SET status='REVOKED',revoked_at=?,revoked_by=?,revoked_by_operator_id=?,version=version+1,updated_at=? WHERE id=?",
                    Timestamp.from(c.now()),nullable(c.productAccountId()),nullable(c.operatorId()),Timestamp.from(c.now()),bytes(source.member()));
            jdbc.update("UPDATE iam_student_staff_reconciliation SET status='RECONCILED',target_account_id=?,target_membership_id=? WHERE organization_id=? AND membership_id=?",bytes(target),bytes(member),bytes(organization),bytes(source.member()));
            jdbc.update("UPDATE organization SET authorization_version=authorization_version+1 WHERE id=?",bytes(organization));
            jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
            for(UUID recipient:List.of(command.sourceAccountId(),target)) jdbc.update("INSERT INTO iam_student_notice VALUES(?,?,?,?,?,?,?)",bytes(UUID.randomUUID()),bytes(organization),bytes(recipient),bytes(member),"STUDENT_STAFF_RECONCILED",version+1,Timestamp.from(c.now()));
            if(operatorMode)operatorGate.audit(new DeveloperOperatorGate.Context(c.operatorId(),c.sessionId(),c.now()),
                    "STUDENT_STAFF_RECONCILED",member,version+1,proof.reason().strip());
            else gate.audit(c.legacy(),proof.accountId(),"STUDENT_STAFF_RECONCILED",member,version+1);
            outbox.lifecycle("ORGANIZATION",organization,version+1,"STUDENT_STAFF_RECONCILED",target,organization,null,c.now());
            outbox.accountProvisioned(target,organization,member,c.now());return new Result(target,member,version+1);
        };
        if(operatorMode) {
            if(operatorGate==null)throw denied();
            return operatorGate.execute(jwt,proof.password(),proof.secondFactor(),null,
                    context->operation.apply(new Actor(context.now(),context.operatorId(),null,context.sessionId(),null)));
        }
        return gate.executeForGroups(jwt,proof.accountId(),proof.password(),proof.secondFactor(),
                "student-staff-reconcile:"+organization+":"+command.sourceAccountId(),groups,
                context->operation.apply(new Actor(context.now(),null,proof.accountId(),context.session().id(),context)));
    }
    private record Source(UUID user,UUID member) { }
    private record Member(UUID id,String status) { }
    private static byte[] nullable(UUID value) { return value==null?null:bytes(value); }
    private static ResponseStatusException bad() { return new ResponseStatusException(HttpStatus.BAD_REQUEST,"INVALID_STUDENT_STAFF_RECONCILIATION"); }
    private static ResponseStatusException denied() { return new ResponseStatusException(HttpStatus.FORBIDDEN,"STUDENT_STAFF_RECONCILIATION_DENIED"); }
    private static ResponseStatusException conflict() { return new ResponseStatusException(HttpStatus.CONFLICT,"STUDENT_STAFF_RECONCILIATION_CONFLICT"); }
}
