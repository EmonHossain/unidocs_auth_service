package com.unidocs.auth.authorization.controlplane;

import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import com.unidocs.auth.account.domain.AccountGroupMember;
import com.unidocs.auth.account.domain.UserAccount;
import com.unidocs.auth.authentication.domain.LoginIdentity;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import jakarta.persistence.EntityManager;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Explicit developer-controlled migration; never reclassifies the existing personal account. */
@Service
@Transactional(propagation=Propagation.NEVER)
public class ProfessionalReconciliationService {
    public record Command(UUID sourceAccountId,UUID targetAccountId,String newAccountPassword,String displayName,long expectedVersion) {
        @Override public String toString() { return "ProfessionalReconciliationCommand[REDACTED]"; }
    }
    public record Result(UUID sourceAccountId,UUID accountId,UUID membershipId,long organizationVersion) { }
    private record Actor(Instant now,UUID operatorId,UUID productAccountId,UUID sessionId,SessionAccess.Context legacy) { }
    private final JdbcTemplate jdbc;private final DeveloperGate gate;private final DeveloperOperatorGate operatorGate;
    private final boolean operatorMode;private final EntityManager entities;
    private final PasswordEncoder passwords;private final OutboxRepository outbox;
    public ProfessionalReconciliationService(JdbcTemplate jdbc,DeveloperGate gate,EntityManager entities,PasswordEncoder passwords,OutboxRepository outbox) {
        this(jdbc,gate,(DeveloperOperatorGate)null,false,entities,passwords,outbox);
    }
    @org.springframework.beans.factory.annotation.Autowired
    public ProfessionalReconciliationService(JdbcTemplate jdbc,DeveloperGate gate,
            org.springframework.beans.factory.ObjectProvider<DeveloperOperatorGate> operatorGates,
            @org.springframework.beans.factory.annotation.Value("${auth.developer.operator.enabled:false}") boolean operatorMode,
            EntityManager entities,PasswordEncoder passwords,OutboxRepository outbox) {
        this(jdbc,gate,operatorGates.getIfAvailable(),operatorMode,entities,passwords,outbox);
    }
    private ProfessionalReconciliationService(JdbcTemplate jdbc,DeveloperGate gate,DeveloperOperatorGate operatorGate,
            boolean operatorMode,EntityManager entities,PasswordEncoder passwords,OutboxRepository outbox) {
        this.jdbc=jdbc;this.gate=gate;this.operatorGate=operatorGate;this.operatorMode=operatorMode;
        this.entities=entities;this.passwords=passwords;this.outbox=outbox;
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    public Result reconcile(Jwt jwt,DeveloperCatalogService.Proof proof,UUID organization,Command command) {
        if(proof==null || command==null || command.sourceAccountId()==null || command.expectedVersion()<1
                || command.sourceAccountId().equals(command.targetAccountId())) throw bad();
        if(operatorMode && (proof.accountId()!=null || proof.reason()==null || proof.reason().isBlank()
                || proof.reason().length()>512))throw bad();
        if(command.targetAccountId()==null && (command.newAccountPassword()==null || command.newAccountPassword().length()<12
                || command.newAccountPassword().length()>128 || command.displayName()==null || command.displayName().isBlank()
                || command.displayName().strip().length()>100 || command.displayName().codePoints().anyMatch(Character::isISOControl))) throw bad();
        if(command.targetAccountId()!=null && (command.newAccountPassword()!=null || command.displayName()!=null)) throw bad();
        List<UUID> groups=jdbc.query("SELECT account_group_id FROM account_group_member WHERE account_id=? AND status='LINKED'",
                (row,index)->uuid(row.getBytes(1)),bytes(command.sourceAccountId()));
        if(groups.size()!=1) throw denied();
        // Hash only the explicitly supplied new secret, outside all SQL transactions.
        String hash=command.targetAccountId()==null?passwords.encode(command.newAccountPassword()):null;
        Function<Actor,Result> operation=context->{
            List<UUID> lockedGroup=jdbc.query("SELECT id FROM account_group WHERE id=? AND status='ACTIVE' FOR UPDATE",
                    (row,index)->uuid(row.getBytes(1)),bytes(groups.getFirst()));
            if(lockedGroup.size()!=1)throw denied();
            jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE",Long.class);
            List<Org> orgs=jdbc.query("SELECT type,authorization_version FROM organization WHERE id=? AND status='ACTIVE' AND type IN('COMPANY','CUSTOM') FOR UPDATE",
                    (row,index)->new Org(row.getString(1),row.getLong(2)),bytes(organization));
            if(orgs.size()!=1) throw denied();Org org=orgs.getFirst();
            List<Result> prior=jdbc.query("SELECT source_account_id,target_account_id,target_membership_id FROM iam_professional_reconciliation WHERE organization_id=? AND source_account_id=?",
                    (row,index)->new Result(uuid(row.getBytes(1)),uuid(row.getBytes(2)),uuid(row.getBytes(3)),org.version()),bytes(organization),bytes(command.sourceAccountId()));
            if(!prior.isEmpty()) {
                Result result=prior.getFirst();
                if(command.targetAccountId()!=null && !command.targetAccountId().equals(result.accountId())) throw conflict();
                return result;
            }
            if(org.version()!=command.expectedVersion()) throw conflict();
            List<Source> sources=jdbc.query("""
                    SELECT a.user_id,m.id,m.role,m.official_email FROM user_account a
                    JOIN users u ON u.id=a.user_id AND u.status='ACTIVE'
                    JOIN organization_membership m ON m.account_id=a.id AND m.organization_id=? AND m.status='ACTIVE'
                    JOIN account_group_member g ON g.account_id=a.id AND g.status='LINKED' AND g.account_group_id=?
                    JOIN account_group owner_group ON owner_group.id=g.account_group_id AND owner_group.user_id=a.user_id AND owner_group.status='ACTIVE'
                    WHERE a.id=? AND a.type='PERSONAL' AND a.status='ACTIVE'
                    AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=m.organization_id AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED','PURGED')) FOR UPDATE
                    """,(row,index)->new Source(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getString(3),row.getString(4)),bytes(organization),bytes(groups.getFirst()),bytes(command.sourceAccountId()));
            if(sources.size()!=1) throw denied();Source source=sources.getFirst();
            UUID target=command.targetAccountId();
            if(target==null) {
                UserAccount account=new UserAccount(UUID.randomUUID(),source.user(),organization,UserAccount.Type.valueOf(org.type()),command.displayName().strip(),context.now());
                entities.persist(account);entities.flush();target=account.id();
                entities.persist(new LoginIdentity(UUID.randomUUID(),target,LoginIdentity.Type.ACCOUNT_ID,target.toString(),hash,context.now()));entities.flush();
                entities.persist(new AccountGroupMember(account,groups.getFirst(),source.user(),command.sourceAccountId(),context.now()));entities.flush();
            } else {
                List<UUID> targets=jdbc.query("SELECT a.id FROM user_account a JOIN account_group_member g ON g.account_id=a.id AND g.status='LINKED' WHERE a.id=? AND a.user_id=? AND a.organization_id=? AND a.type=? AND a.status='ACTIVE' AND g.account_group_id=? FOR UPDATE",
                        (row,index)->uuid(row.getBytes(1)),bytes(target),bytes(source.user()),bytes(organization),org.type(),bytes(groups.getFirst()));
                if(targets.size()!=1) throw denied();
            }
            UUID member;
            List<Membership> memberships=jdbc.query("SELECT id,status FROM organization_membership WHERE organization_id=? AND account_id=? FOR UPDATE",
                    (row,index)->new Membership(uuid(row.getBytes(1)),row.getString(2)),bytes(organization),bytes(target));
            if(memberships.isEmpty()) {
                member=UUID.randomUUID();
                jdbc.update("INSERT INTO organization_membership(id,organization_id,account_id,role,status,official_email,version,joined_at,created_at,updated_at) VALUES(?,?,?,?,'ACTIVE',?,1,?,?,?)",
                        bytes(member),bytes(organization),bytes(target),source.role(),source.email(),Timestamp.from(context.now()),Timestamp.from(context.now()),Timestamp.from(context.now()));
            } else {
                if(!memberships.getFirst().status().equals("ACTIVE")) throw denied();member=memberships.getFirst().id();
            }
            Integer groupCount=jdbc.queryForObject("SELECT COUNT(*) FROM group_membership WHERE organization_id=? AND organization_membership_id=? AND status='ACTIVE'",Integer.class,bytes(organization),bytes(source.membership()));
            if(groupCount==null || groupCount>128) throw new ResponseStatusException(HttpStatus.CONFLICT,"RECONCILIATION_GROUP_LIMIT_EXCEEDED");
            jdbc.update("""
                    INSERT INTO group_membership(id,organization_id,group_id,account_id,organization_membership_id,role,membership_type,source,status,
                        valid_from,valid_until,version,assigned_by_account_id,assigned_by_operator_id,assignment_request_id,assignment_fingerprint,created_at,updated_at,can_manage_group)
                    SELECT UUID_TO_BIN(UUID()),gm.organization_id,gm.group_id,?,?,gm.role,gm.membership_type,'ORGANIZATION_ASSIGNMENT','ACTIVE',
                        gm.valid_from,gm.valid_until,1,?, ?,UUID_TO_BIN(UUID()),SHA2(CONCAT('professional-reconciliation:',HEX(gm.id)),256),?,?,FALSE
                    FROM group_membership gm JOIN iam_group g ON g.id=gm.group_id AND g.organization_id=gm.organization_id AND g.status='ACTIVE'
                    WHERE gm.organization_id=? AND gm.organization_membership_id=? AND gm.status='ACTIVE'
                    AND (gm.valid_until IS NULL OR gm.valid_until>?)
                    AND NOT EXISTS(SELECT 1 FROM group_membership target WHERE target.group_id=gm.group_id AND target.organization_membership_id=?)
                    """,bytes(target),bytes(member),nullable(context.productAccountId()),nullable(context.operatorId()),Timestamp.from(context.now()),Timestamp.from(context.now()),bytes(organization),bytes(source.membership()),Timestamp.from(context.now()),bytes(member));
            jdbc.update("INSERT INTO iam_professional_assignment(id,organization_id,membership_id,account_id,group_id,role_id,status,valid_from,valid_until,version) SELECT UUID_TO_BIN(UUID()),source_assignment.organization_id,?,?,source_assignment.group_id,source_assignment.role_id,'ACTIVE',source_assignment.valid_from,source_assignment.valid_until,1 FROM iam_professional_assignment source_assignment WHERE source_assignment.organization_id=? AND source_assignment.membership_id=? AND source_assignment.status='ACTIVE' AND (source_assignment.valid_until IS NULL OR source_assignment.valid_until>?) ON DUPLICATE KEY UPDATE status=iam_professional_assignment.status",
                    bytes(member),bytes(target),bytes(organization),bytes(source.membership()),Timestamp.from(context.now()));
            // Carry explicit source blocks forward; reconciliation must not evade an account-scoped deny.
            jdbc.update("""
                    INSERT INTO iam_professional_restriction(id,organization_id,group_id,account_id,operation_id,status,valid_from,valid_until,version)
                    SELECT UUID_TO_BIN(UUID()),source_restriction.organization_id,source_restriction.group_id,?,source_restriction.operation_id,'ACTIVE',source_restriction.valid_from,source_restriction.valid_until,1
                    FROM iam_professional_restriction source_restriction WHERE source_restriction.organization_id=? AND source_restriction.account_id=? AND source_restriction.status='ACTIVE'
                    AND (source_restriction.valid_until IS NULL OR source_restriction.valid_until>?)
                    ON DUPLICATE KEY UPDATE status='ACTIVE',valid_from=LEAST(iam_professional_restriction.valid_from,VALUES(valid_from)),
                    valid_until=IF(iam_professional_restriction.valid_until IS NULL OR VALUES(valid_until) IS NULL,NULL,GREATEST(iam_professional_restriction.valid_until,VALUES(valid_until))),version=iam_professional_restriction.version+1
                    """,bytes(target),bytes(organization),bytes(command.sourceAccountId()),Timestamp.from(context.now()));
            jdbc.update("INSERT INTO iam_operation_restriction(id,operation_id,category_key,account_id,status,version,valid_from,valid_until) SELECT UUID_TO_BIN(UUID()),operation_id,category_key,?,'ACTIVE',1,valid_from,valid_until FROM iam_operation_restriction WHERE account_id=? AND category_key='ORGANIZATION' AND status='ACTIVE' AND (valid_until IS NULL OR valid_until>?)",
                    bytes(target),bytes(command.sourceAccountId()),Timestamp.from(context.now()));
            jdbc.update("UPDATE iam_professional_assignment SET status='REVOKED',version=version+1 WHERE organization_id=? AND membership_id=? AND status='ACTIVE'",bytes(organization),bytes(source.membership()));
            jdbc.update("UPDATE group_membership SET status='REVOKED',version=version+1,revoked_at=?,revoked_by_account_id=?,revoked_by_operator_id=?,updated_at=? WHERE organization_id=? AND organization_membership_id=? AND status='ACTIVE'",
                    Timestamp.from(context.now()),nullable(context.productAccountId()),nullable(context.operatorId()),Timestamp.from(context.now()),bytes(organization),bytes(source.membership()));
            jdbc.update("UPDATE organization_membership SET status='REVOKED',version=version+1,revoked_at=?,revoked_by=?,revoked_by_operator_id=?,updated_at=? WHERE id=?",
                    Timestamp.from(context.now()),nullable(context.productAccountId()),nullable(context.operatorId()),Timestamp.from(context.now()),bytes(source.membership()));
            long version=org.version()+1;
            jdbc.update("UPDATE organization SET authorization_version=?,updated_at=? WHERE id=?",version,Timestamp.from(context.now()),bytes(organization));
            jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
            jdbc.update("INSERT INTO iam_professional_reconciliation(organization_id,source_account_id,target_account_id,source_membership_id,target_membership_id,developer_account_id,developer_operator_id,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    bytes(organization),bytes(command.sourceAccountId()),bytes(target),bytes(source.membership()),bytes(member),
                    nullable(context.productAccountId()),nullable(context.operatorId()),Timestamp.from(context.now()));
            jdbc.update("INSERT INTO iam_professional_notice VALUES(?,?,?,?,?,?)",bytes(UUID.randomUUID()),bytes(organization),bytes(target),version,"PROFESSIONAL_ACCOUNT_RECONCILED",Timestamp.from(context.now()));
            jdbc.update("INSERT INTO iam_professional_notice VALUES(?,?,?,?,?,?)",bytes(UUID.randomUUID()),bytes(organization),bytes(command.sourceAccountId()),version,"PROFESSIONAL_ACCOUNT_RECONCILED",Timestamp.from(context.now()));
            if(operatorMode)operatorGate.audit(new DeveloperOperatorGate.Context(context.operatorId(),context.sessionId(),context.now()),
                    "PROFESSIONAL_ACCOUNT_RECONCILED",target,version,proof.reason().strip());
            else gate.audit(context.legacy(),proof.accountId(),"PROFESSIONAL_ACCOUNT_RECONCILED",target,version);
            outbox.professionalReconciled(organization,version,command.sourceAccountId(),target,source.membership(),member,context.now());
            Long global=jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL'",Long.class);
            outbox.lifecycle("IAM_POLICY",organization,global,"IAM_POLICY_CHANGED",context.productAccountId(),organization,null,context.now());
            outbox.accountProvisioned(target,organization,member,context.now());
            return new Result(command.sourceAccountId(),target,member,version);
        };
        if(operatorMode) {
            if(proof.accountId()!=null || operatorGate==null)throw denied();
            return operatorGate.execute(jwt,proof.password(),proof.secondFactor(),null,
                    context->operation.apply(new Actor(context.now(),context.operatorId(),null,context.sessionId(),null)));
        }
        return gate.executeForGroups(jwt,proof.accountId(),proof.password(),proof.secondFactor(),
                "professional-reconcile:"+organization+":"+command.sourceAccountId(),groups,
                context->operation.apply(new Actor(context.now(),null,proof.accountId(),context.session().id(),context)));
    }
    private record Org(String type,long version) { }
    private record Source(UUID user,UUID membership,String role,String email) { }
    private record Membership(UUID id,String status) { }
    private static byte[] nullable(UUID value) { return value==null?null:bytes(value); }
    private static UUID uuid(byte[] value) { ByteBuffer b=ByteBuffer.wrap(value);return new UUID(b.getLong(),b.getLong()); }
    private static ResponseStatusException bad() { return new ResponseStatusException(HttpStatus.BAD_REQUEST,"INVALID_PROFESSIONAL_RECONCILIATION"); }
    private static ResponseStatusException denied() { return new ResponseStatusException(HttpStatus.FORBIDDEN,"PROFESSIONAL_RECONCILIATION_DENIED"); }
    private static ResponseStatusException conflict() { return new ResponseStatusException(HttpStatus.CONFLICT,"PROFESSIONAL_RECONCILIATION_CONFLICT"); }
}
