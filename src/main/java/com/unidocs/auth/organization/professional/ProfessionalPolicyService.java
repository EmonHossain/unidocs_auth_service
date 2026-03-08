package com.unidocs.auth.organization.professional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.BiFunction;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import com.unidocs.auth.authorization.application.ProfessionalAuthorizationService;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Service
@Transactional(propagation=Propagation.NEVER)
public class ProfessionalPolicyService {
    public record Responsibility(@NotNull UUID accountId,@NotNull UUID targetAccountId,UUID groupId,
            @NotNull UUID roleId,boolean active,Instant validUntil,@Positive long expectedVersion) { }
    public record Restriction(@NotNull UUID accountId,UUID targetAccountId,UUID groupId,
            @NotNull UUID operationId,boolean active,Instant validUntil,@Positive long expectedVersion) { }
    public record Notice(UUID id,UUID organizationId,long authorizationVersion,String eventType,Instant createdAt) { }
    private final SessionAccess access;
    private final ProfessionalAuthorizationService authorization;
    private final JdbcTemplate jdbc;
    private final SessionRepository sessions;
    private final OutboxRepository outbox;
    private final com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary;
    @Autowired
    public ProfessionalPolicyService(SessionAccess access,ProfessionalAuthorizationService authorization,JdbcTemplate jdbc,
            SessionRepository sessions,OutboxRepository outbox,
            ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> canaryProvider) {
        this(access,authorization,jdbc,sessions,outbox,canaryProvider.getIfAvailable());
    }
    public ProfessionalPolicyService(SessionAccess access,ProfessionalAuthorizationService authorization,JdbcTemplate jdbc,
            SessionRepository sessions,OutboxRepository outbox) {
        this(access,authorization,jdbc,sessions,outbox,(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary)null);
    }
    private ProfessionalPolicyService(SessionAccess access,ProfessionalAuthorizationService authorization,JdbcTemplate jdbc,
            SessionRepository sessions,OutboxRepository outbox,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary) {
        this.access=access;this.authorization=authorization;this.jdbc=jdbc;this.sessions=sessions;this.outbox=outbox;
        this.canary=canary;
    }
    /**
     * Changes an eligible predefined responsibility with current target and scope-membership admission.
     * @param sid authenticated session
     * @param subject authenticated login account
     * @param organization verified tenant
     * @param request expected-version responsibility change
     * @return committed organization authorization version
     * @throws OperationAuthorizationFailure when admission, scope, policy or expected version fails
     */
    public long responsibility(UUID sid,UUID subject,UUID organization,Responsibility request) {
        if(request==null || request.accountId()==null || request.targetAccountId()==null || request.roleId()==null || request.expectedVersion()<1) throw invalid();
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision=
                checkCanary(sid,subject,organization,request.accountId(),null,"organization.responsibility.assign");
        return access.execute(sid,subject,context->{
            authorization.admit(context,request.accountId(),organization);
            fence(organization,request.expectedVersion());
            if(canary!=null)canary.requireDecision(organization,null,"organization.responsibility.assign",canaryDecision);
            if(canaryDecision==null || !canaryDecision.enforcing())
                authorization.require(context,request.accountId(),organization,null,"auth-service","organization.responsibility.assign");
            if(canaryDecision!=null)canary.revalidate(canaryDecision,context,request.accountId(),organization);
            window(context.now(),request.validUntil());
            UUID member=request.active()?member(organization,request.targetAccountId()):assignmentMember(organization,request);
            if(request.active()) authorization.ancestors(organization,request.groupId());
            String kind=request.groupId()==null?"ORGANIZATION":jdbc.queryForObject("SELECT IF(type='DEPARTMENT','DEPARTMENT','TEAM') FROM iam_group WHERE organization_id=? AND id=?",String.class,bytes(organization),bytes(request.groupId()));
            Integer eligible=jdbc.queryForObject("SELECT COUNT(*) FROM iam_professional_responsibility p JOIN iam_role r ON r.id=p.role_id WHERE p.role_id=? AND p.scope_kind=? AND (r.status='ACTIVE' OR ?=FALSE)",Integer.class,bytes(request.roleId()),kind,request.active());
            if(eligible==null || eligible!=1) throw denied();
            if(request.active() && request.groupId()!=null) {
                authorization.requireScopeMember(organization,request.groupId(),request.targetAccountId());
            }
            jdbc.update("""
                    INSERT INTO iam_professional_assignment(id,organization_id,membership_id,account_id,group_id,role_id,status,valid_from,valid_until)
                    VALUES(?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE status=VALUES(status),valid_from=VALUES(valid_from),valid_until=VALUES(valid_until),version=version+1
                    """,bytes(UUID.randomUUID()),bytes(organization),bytes(member),bytes(request.targetAccountId()),nullable(request.groupId()),bytes(request.roleId()),request.active()?"ACTIVE":"REVOKED",Timestamp.from(context.now()),time(request.validUntil()));
            return changed(context,request.accountId(),organization,request.targetAccountId(),"PROFESSIONAL_RESPONSIBILITY_CHANGED");
        });
    }
    public long restriction(UUID sid,UUID subject,UUID organization,Restriction request) {
        if(request==null || request.accountId()==null || request.operationId()==null || request.expectedVersion()<1) throw invalid();
        String selected=canary!=null && canary.applies(organization,"organization.access.update")
                ? scopeOperation(organization,request.groupId()):null;
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision=selected==null?null:
                checkCanary(sid,subject,organization,request.accountId(),request.groupId(),selected);
        return access.execute(sid,subject,context->{
            authorization.admit(context,request.accountId(),organization);
            fence(organization,request.expectedVersion());
            String operation=request.groupId()==null?"organization.access.update":jdbc.queryForObject("SELECT IF(type='DEPARTMENT','department.access.update','team.access.update') FROM iam_group WHERE organization_id=? AND id=?",String.class,bytes(organization),bytes(request.groupId()));
            if(canary!=null)canary.requireDecision(organization,request.groupId(),operation,canaryDecision);
            if(canaryDecision==null || !canaryDecision.enforcing())
                authorization.require(context,request.accountId(),organization,request.groupId(),"auth-service",operation);
            if(canaryDecision!=null)canary.revalidate(canaryDecision,context,request.accountId(),organization);
            authorization.ancestors(organization,request.groupId());window(context.now(),request.validUntil());
            if(request.targetAccountId()!=null) {
                member(organization,request.targetAccountId());
                if(request.groupId()!=null) authorization.requireScopeMember(organization,request.groupId(),request.targetAccountId());
            }
            // Local access controls target content operations, never the developer control plane or membership assignment.
            Integer content=jdbc.queryForObject("SELECT COUNT(*) FROM iam_operation WHERE id=? AND status='ACTIVE' AND (service_id='document-service' AND (operation_key LIKE 'file.%' OR operation_key LIKE 'folder.%' OR operation_key LIKE 'publication.%' OR operation_key='workspace.read') OR service_id='auth-service' AND operation_key='organization.collaboration.invite')",Integer.class,bytes(request.operationId()));
            if(content==null || content!=1) throw denied();
            jdbc.update("""
                    INSERT INTO iam_professional_restriction(id,organization_id,group_id,account_id,operation_id,status,valid_from,valid_until)
                    VALUES(?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE status=VALUES(status),valid_from=VALUES(valid_from),valid_until=VALUES(valid_until),version=version+1
                    """,bytes(UUID.randomUUID()),bytes(organization),nullable(request.groupId()),nullable(request.targetAccountId()),bytes(request.operationId()),request.active()?"ACTIVE":"REVOKED",Timestamp.from(context.now()),time(request.validUntil()));
            return changed(context,request.accountId(),organization,request.targetAccountId(),"PROFESSIONAL_ACCESS_CHANGED");
        });
    }
    public List<Notice> notices(UUID sid,UUID subject,UUID account,UUID after,int limit) {
        if(limit<1 || limit>100) throw new IllegalArgumentException("Invalid page size");
        return access.execute(sid,subject,context->{
            sessions.liveGrant(context.session(),account,context.now()).orElseThrow(ProfessionalPolicyService::denied);
            return jdbc.query("SELECT id,organization_id,authorization_version,event_type,created_at FROM iam_professional_notice WHERE recipient_account_id=? AND id>? ORDER BY id LIMIT ?",
                    (row,index)->new Notice(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getLong(3),row.getString(4),row.getTimestamp(5).toInstant()),bytes(account),bytes(after==null?new UUID(0,0):after),limit);
        });
    }
    public record Member(UUID membershipId,UUID accountId,String displayName,long version) { }
    public record ResponsibilityView(UUID id,UUID accountId,UUID groupId,UUID roleId,String scopeKind,String status,long version) { }
    public record RestrictionView(UUID id,UUID accountId,UUID groupId,UUID operationId,String status,long version) { }
    public record ProjectionStatus(long requiredRevision,long appliedRevision,long requiredSourceVersion,
            long appliedSourceVersion,String status) { }
    public record AccessOption(UUID id,String key,String scopeKind) { }
    public record AccessCatalog(List<AccessOption> responsibilities,List<AccessOption> restrictionOperations) { }
    public record AccessPreview(UUID targetAccountId,UUID operationId,String decision,long authorizationVersion) { }
    public record AuditEntry(UUID id,UUID actorAccountId,UUID targetAccountId,String action,long authorizationVersion,Instant createdAt) { }
    /** Checks one configured operation for a currently eligible member within the manager's scope.
     * @param sid current product session
     * @param subject current product user
     * @param organization selected organization
     * @param account manager's selected account
     * @param target member whose access is being previewed
     * @param group optional managed group scope
     * @param operation configured operation ID
     * @return redacted allow or deny decision with current organization version
     */
    public AccessPreview preview(UUID sid,UUID subject,UUID organization,UUID account,UUID target,UUID group,UUID operation) {
        if(target==null || operation==null)throw invalid();
        return readWithCanary(sid,subject,organization,account,group,(context,decision)->{
            readScope(context,organization,account,group,decision);
            member(organization,target);
            if(group!=null)authorization.requireScopeMember(organization,group,target);
            List<AccessOption> selected=jdbc.query("""
                    SELECT id,operation_key,service_id FROM iam_operation WHERE id=? AND status='ACTIVE'
                    AND (service_id='document-service' AND (operation_key LIKE 'file.%' OR operation_key LIKE 'folder.%'
                         OR operation_key LIKE 'publication.%' OR operation_key='workspace.read')
                         OR service_id='auth-service' AND operation_key='organization.collaboration.invite')
                    """,(row,index)->new AccessOption(uuid(row.getBytes(1)),row.getString(2),row.getString(3)),bytes(operation));
            if(selected.size()!=1)throw denied();AccessOption choice=selected.getFirst();
            boolean allowed=authorization.previewTarget(organization,target,group,choice.scopeKind(),choice.key());
            Long version=jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=? AND status='ACTIVE'",Long.class,bytes(organization));
            if(version==null)throw denied();
            return new AccessPreview(target,operation,allowed?"ALLOWED":"DENIED",version);
        });
    }
    /** Lists only access-management audit metadata for the current organization manager.
     * @param sid current product session
     * @param subject current product user
     * @param organization selected organization
     * @param account manager's selected account
     * @param after exclusive audit cursor
     * @param limit bounded page size
     * @return authorized audit metadata without content identifiers
     */
    public List<AuditEntry> audit(UUID sid,UUID subject,UUID organization,UUID account,UUID after,int limit) {
        page(limit);
        return readWithCanary(sid,subject,organization,account,null,(context,decision)->{
            readScope(context,organization,account,null,decision);
            return jdbc.query("SELECT id,actor_account_id,target_account_id,event_type,authorization_version,created_at FROM iam_professional_audit WHERE organization_id=? AND id>? ORDER BY id LIMIT ?",
                    (row,index)->new AuditEntry(uuid(row.getBytes(1)),uuid(row.getBytes(2)),optional(row.getBytes(3)),
                            row.getString(4),row.getLong(5),row.getTimestamp(6).toInstant()),bytes(organization),cursor(after),limit);
        });
    }
    /** Lists only configured business choices after current scope management admission.
     * @param sid current product session
     * @param subject current product user
     * @param organization selected organization
     * @param account selected account grant
     * @return configured scoped access choices
     */
    public AccessCatalog accessCatalog(UUID sid,UUID subject,UUID organization,UUID account) {
        return readWithCanary(sid,subject,organization,account,null,(context,decision)->{
            readScope(context,organization,account,null,decision);
            List<AccessOption> roles=jdbc.query("SELECT p.role_id,r.role_key,p.scope_kind FROM iam_professional_responsibility p JOIN iam_role r ON r.id=p.role_id WHERE r.status='ACTIVE' ORDER BY p.scope_kind,r.role_key",
                    (row,index)->new AccessOption(uuid(row.getBytes(1)),row.getString(2),row.getString(3)));
            List<AccessOption> operations=jdbc.query("SELECT id,operation_key,service_id FROM iam_operation WHERE status='ACTIVE' AND (service_id='document-service' AND (operation_key LIKE 'file.%' OR operation_key LIKE 'folder.%' OR operation_key LIKE 'publication.%' OR operation_key='workspace.read') OR service_id='auth-service' AND operation_key='organization.collaboration.invite') ORDER BY operation_key",
                    (row,index)->new AccessOption(uuid(row.getBytes(1)),row.getString(2),row.getString(3)));
            return new AccessCatalog(List.copyOf(roles),List.copyOf(operations));
        });
    }
    /** Returns only non-secret synchronization evidence for a currently authorized scope manager.
     * @param sid current product session
     * @param subject current product user
     * @param organization selected organization
     * @param account selected account grant
     * @return required and applied projection versions
     */
    public ProjectionStatus projectionStatus(UUID sid,UUID subject,UUID organization,UUID account) {
        return readWithCanary(sid,subject,organization,account,null,(context,decision)->{
            readScope(context,organization,account,null,decision);
            List<ProjectionStatus> states=jdbc.query("SELECT required_revision,applied_revision,required_source_version,applied_source_version,sync_status FROM spicedb_organization_sync_state WHERE organization_id=?",
                    (row,index)->new ProjectionStatus(row.getLong(1),row.getLong(2),row.getLong(3),row.getLong(4),row.getString(5)),bytes(organization));
            if(states.size()!=1) throw new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE,"PROJECTION_STATE_UNAVAILABLE");
            return states.getFirst();
        });
    }
    public List<Member> members(UUID sid,UUID subject,UUID organization,UUID account,UUID group,UUID after,int limit) {
        page(limit);
        return readWithCanary(sid,subject,organization,account,group,(context,decision)->{
            readScope(context,organization,account,group,decision);
            return jdbc.query("""
                    SELECT m.id,m.account_id,a.display_name,m.version FROM organization_membership m
                    JOIN user_account a ON a.id=m.account_id AND a.organization_id=m.organization_id AND a.status='ACTIVE' AND a.type IN('COMPANY','CUSTOM')
                    JOIN users u ON u.id=a.user_id AND u.status='ACTIVE'
                    WHERE m.organization_id=? AND m.status='ACTIVE' AND m.id>?
                    AND (? IS NULL OR EXISTS(SELECT 1 FROM group_membership gm WHERE gm.organization_id=m.organization_id AND gm.organization_membership_id=m.id AND gm.group_id=? AND gm.status='ACTIVE' AND gm.valid_from<=? AND (gm.valid_until IS NULL OR gm.valid_until>?)))
                    AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=m.organization_id AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED','PURGED'))
                    ORDER BY m.id LIMIT ?
                    """,(row,index)->new Member(uuid(row.getBytes(1)),uuid(row.getBytes(2)),row.getString(3),row.getLong(4)),bytes(organization),cursor(after),nullable(group),nullable(group),Timestamp.from(context.now()),Timestamp.from(context.now()),limit);
        });
    }
    public List<ResponsibilityView> responsibilities(UUID sid,UUID subject,UUID organization,UUID account,UUID group,UUID after,int limit) {
        page(limit);
        return readWithCanary(sid,subject,organization,account,group,(context,decision)->{
            readScope(context,organization,account,group,decision);
            return jdbc.query("SELECT a.id,a.account_id,a.group_id,a.role_id,p.scope_kind,a.status,a.version FROM iam_professional_assignment a JOIN iam_professional_responsibility p ON p.role_id=a.role_id WHERE a.organization_id=? AND a.group_id<=>? AND a.id>? ORDER BY a.id LIMIT ?",
                    (row,index)->new ResponsibilityView(uuid(row.getBytes(1)),uuid(row.getBytes(2)),optional(row.getBytes(3)),uuid(row.getBytes(4)),row.getString(5),row.getString(6),row.getLong(7)),bytes(organization),nullable(group),cursor(after),limit);
        });
    }
    public List<RestrictionView> restrictions(UUID sid,UUID subject,UUID organization,UUID account,UUID group,UUID after,int limit) {
        page(limit);
        return readWithCanary(sid,subject,organization,account,group,(context,decision)->{
            readScope(context,organization,account,group,decision);
            return jdbc.query("SELECT id,account_id,group_id,operation_id,status,version FROM iam_professional_restriction WHERE organization_id=? AND group_id<=>? AND id>? ORDER BY id LIMIT ?",
                    (row,index)->new RestrictionView(uuid(row.getBytes(1)),optional(row.getBytes(2)),optional(row.getBytes(3)),uuid(row.getBytes(4)),row.getString(5),row.getLong(6)),bytes(organization),nullable(group),cursor(after),limit);
        });
    }
    private void readScope(SessionAccess.Context context,UUID organization,UUID account,UUID group,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision) {
        authorization.admit(context,account,organization);
        String operation=group==null?"organization.access.update":jdbc.queryForObject("SELECT IF(type='DEPARTMENT','department.access.update','team.access.update') FROM iam_group WHERE organization_id=? AND id=?",String.class,bytes(organization),bytes(group));
        if(canary!=null)canary.requireDecision(organization,group,operation,decision);
        if(decision==null || !decision.enforcing())
            authorization.require(context,account,organization,group,"auth-service",operation);
    }
    private <T> T readWithCanary(UUID sid,UUID subject,UUID organization,UUID account,UUID group,
            BiFunction<SessionAccess.Context,com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision,T> reader) {
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=null;
        if(canary!=null && canary.applies(organization,"organization.access.update")) {
            decision=checkCanary(sid,subject,organization,account,group,scopeOperation(organization,group));
        }
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision checked=decision;
        return access.execute(sid,subject,context->{
            if(checked!=null)canary.revalidate(checked,context,account,organization);
            return reader.apply(context,checked);
        });
    }
    private com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision checkCanary(
            UUID sid,UUID subject,UUID organization,UUID account,UUID group,String operation) {
        return canary!=null && canary.applies(organization,operation)
                ? canary.check(sid,subject,account,organization,group,operation):null;
    }
    private String scopeOperation(UUID organization,UUID group) {
        if(group==null)return "organization.access.update";
        List<String> types=jdbc.query("SELECT type FROM iam_group WHERE organization_id=? AND id=? AND status='ACTIVE' AND workspace_context='ORGANIZATION'",
                (row,index)->row.getString(1),bytes(organization),bytes(group));
        if(types.size()!=1)throw denied();
        return "DEPARTMENT".equals(types.getFirst())?"department.access.update":"team.access.update";
    }
    private static void page(int limit) { if(limit<1 || limit>100) throw new IllegalArgumentException("Invalid page size"); }
    private static byte[] cursor(UUID value) { return bytes(value==null?new UUID(0,0):value); }
    private static UUID optional(byte[] value) { return value==null?null:uuid(value); }
    private void fence(UUID organization,long version) {
        jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE",Long.class);
        Long current=jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=? FOR UPDATE",Long.class,bytes(organization));
        if(current==null || current!=version) throw new OperationAuthorizationFailure(HttpStatus.CONFLICT,"PROFESSIONAL_VERSION_CONFLICT");
    }
    /**
     * Locks a current target membership with the same tenant and lifecycle admission used by projection.
     * @param org verified organization
     * @param account target account
     * @return current organization-membership identity
     * @throws OperationAuthorizationFailure when the target is unavailable or belongs to another context
     */
    private UUID member(UUID org,UUID account) {
        List<UUID> found=jdbc.query("""
                SELECT m.id FROM organization_membership m
                JOIN organization o ON o.id=m.organization_id AND o.status='ACTIVE'
                JOIN user_account a ON a.id=m.account_id AND a.organization_id=m.organization_id
                  AND a.status='ACTIVE' AND a.type=o.type AND a.type IN('COMPANY','CUSTOM')
                JOIN users u ON u.id=a.user_id AND u.status='ACTIVE'
                WHERE m.organization_id=? AND m.account_id=? AND m.status='ACTIVE'
                  AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=m.organization_id
                    AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED','PURGED')) FOR SHARE
                """,
                (row,index)->uuid(row.getBytes(1)),bytes(org),bytes(account));
        if(found.size()!=1) throw denied();return found.getFirst();
    }
    private UUID assignmentMember(UUID organization,Responsibility request) {
        List<UUID> members=jdbc.query("SELECT membership_id FROM iam_professional_assignment WHERE organization_id=? AND account_id=? AND group_id<=>? AND role_id=? FOR UPDATE",
                (row,index)->uuid(row.getBytes(1)),bytes(organization),bytes(request.targetAccountId()),nullable(request.groupId()),bytes(request.roleId()));
        if(members.size()!=1) throw denied();return members.getFirst();
    }
    private long changed(SessionAccess.Context context,UUID actor,UUID org,UUID target,String event) {
        jdbc.update("UPDATE organization SET authorization_version=authorization_version+1,updated_at=? WHERE id=?",Timestamp.from(context.now()),bytes(org));
        jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
        Long version=jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(org));
        // Per-recipient durable notice without document names, contents or private-space identifiers.
        jdbc.update("INSERT INTO iam_professional_notice(id,organization_id,recipient_account_id,authorization_version,event_type,created_at) SELECT UUID_TO_BIN(UUID()),organization_id,account_id,?,?,? FROM organization_membership WHERE organization_id=? AND status='ACTIVE' AND (? IS NULL OR account_id=?)",
                version,event,Timestamp.from(context.now()),bytes(org),nullable(target),nullable(target));
        jdbc.update("INSERT INTO iam_professional_audit VALUES(?,?,?,?,?,?,?,?)",bytes(UUID.randomUUID()),bytes(org),bytes(actor),bytes(context.session().id()),nullable(target),event,version,Timestamp.from(context.now()));
        outbox.lifecycle("ORGANIZATION",org,version,event,target,org,null,context.now());
        Long global=jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL'",Long.class);
        outbox.lifecycle("IAM_POLICY",org,global,"IAM_POLICY_CHANGED",actor,org,null,context.now());return version;
    }
    private static void window(Instant now,Instant until) {
        if(until!=null && (!until.isAfter(now) || until.getNano()%1000!=0 || until.isAfter(Instant.parse("9999-12-31T23:59:59Z")))) throw invalid();
    }
    private static byte[] nullable(UUID value) { return value==null?null:bytes(value); }
    private static Timestamp time(Instant value) { return value==null?null:Timestamp.from(value); }
    private static UUID uuid(byte[] value) { java.nio.ByteBuffer b=java.nio.ByteBuffer.wrap(value);return new UUID(b.getLong(),b.getLong()); }
    private static OperationAuthorizationFailure denied() { return new OperationAuthorizationFailure(HttpStatus.FORBIDDEN,"PROFESSIONAL_SCOPE_DENIED"); }
    private static OperationAuthorizationFailure invalid() { return new OperationAuthorizationFailure(HttpStatus.BAD_REQUEST,"INVALID_PROFESSIONAL_COMMAND"); }
}
