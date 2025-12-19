package com.unidocs.auth.authorization.application;

import java.nio.ByteBuffer;
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
import com.unidocs.auth.authorization.domain.OperationAuthorityEvidence;
import com.unidocs.auth.authorization.domain.OperationAuthorityPolicy;
import com.unidocs.auth.authorization.domain.OperationPolicySnapshot;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Current IAM admission and legacy or graph-witness matching under the selected-session/account-group fence. */
@Service
@Transactional(propagation=Propagation.MANDATORY)
public class ProfessionalAuthorizationService {
    private final JdbcTemplate jdbc;
    private final SessionRepository sessions;
    private final OrganizationRepository organizations;
    private final OperationPolicyCatalogRepository policies;
    private final Clock clock;
    private final ObjectProvider<ProfessionalSpiceDbCanary> canaries;

    /**
     * Configures current IAM checks and lazy access to the server-selected graph enforcement policy.
     * @param jdbc owning Auth database access
     * @param sessions current session and grant persistence
     * @param organizations tenant membership persistence
     * @param policies current operation catalog
     * @param clock authorization clock
     * @param canaries optional canary, resolved only when evaluating an operation to avoid a dependency cycle
     */
    @Autowired
    public ProfessionalAuthorizationService(JdbcTemplate jdbc, SessionRepository sessions,
            OrganizationRepository organizations, OperationPolicyCatalogRepository policies, Clock clock,
            ObjectProvider<ProfessionalSpiceDbCanary> canaries) {
        this.jdbc=jdbc; this.sessions=sessions; this.organizations=organizations; this.policies=policies; this.clock=clock;
        this.canaries=canaries;
    }

    /**
     * Configures standalone legacy evaluation without Spring graph enforcement wiring.
     * @param jdbc owning Auth database access
     * @param sessions current session and grant persistence
     * @param organizations tenant membership persistence
     * @param policies current operation catalog
     * @param clock authorization clock
     */
    public ProfessionalAuthorizationService(JdbcTemplate jdbc, SessionRepository sessions,
            OrganizationRepository organizations, OperationPolicyCatalogRepository policies, Clock clock) {
        this(jdbc,sessions,organizations,policies,clock,null);
    }

    public boolean professional(UUID organization) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM organization WHERE id=? AND type<>'UNIVERSITY')",Boolean.class,bytes(organization)));
    }
    /** Admission filter before selector/version reads; the protected operation still performs its full current check. */
    public void admit(SessionAccess.Context context,UUID account,UUID organization) {
        sessions.liveGrant(context.session(),account,clock.instant()).orElseThrow(ProfessionalAuthorizationService::denied);
        Boolean eligible=jdbc.queryForObject("""
                SELECT EXISTS(SELECT 1 FROM user_account a JOIN organization o ON o.id=a.organization_id
                JOIN organization_membership m ON m.account_id=a.id AND m.organization_id=o.id
                WHERE a.id=? AND a.user_id=? AND a.organization_id=? AND a.type=o.type AND a.type IN('COMPANY','CUSTOM')
                AND a.status='ACTIVE' AND o.status='ACTIVE' AND m.status='ACTIVE'
                AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=o.id AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED','PURGED')))
                """,Boolean.class,bytes(account),bytes(context.owner().userId()),bytes(organization));
        if(!Boolean.TRUE.equals(eligible)) throw denied();
    }

    /**
     * Requires current legacy authority only when the operation has not selected graph enforcement.
     * @param context locked session context
     * @param account selected account
     * @param organization verified tenant
     * @param group optional verified group scope
     * @param service registered service
     * @param operation registered operation
     * @return current legacy authorization evidence
     * @throws OperationAuthorizationFailure when denied or graph enforcement requires the canary boundary
     */
    public OperationAuthorizationResponse require(SessionAccess.Context context, UUID account, UUID organization,
            UUID group, String service, String operation) {
        return require(context,account,organization,group,service,operation,false);
    }
    /**
     * Requires current legacy authority with the registered resource-relationship exception, when permitted.
     * @param context locked session context
     * @param account selected account
     * @param organization verified tenant
     * @param group optional verified group scope
     * @param service registered service
     * @param operation registered operation
     * @param exactResourceAccess whether the registered Document operation supplies an exact resource relationship
     * @return current legacy authorization evidence
     * @throws OperationAuthorizationFailure when denied or graph enforcement requires the canary boundary
     */
    public OperationAuthorizationResponse require(SessionAccess.Context context,UUID account,UUID organization,
            UUID group,String service,String operation,boolean exactResourceAccess) {
        return requireInternal(context,account,organization,group,service,operation,exactResourceAccess,true,null,false);
    }

    /**
     * Reads current professional authority without recording session activity.
     * @param context authenticated session context
     * @param account selected account ID
     * @param organization verified organization ID
     * @param group verified group scope, or null for the organization
     * @param service registered service ID
     * @param operation registered operation key
     * @return current operation evidence for an external authorization check
     * @throws OperationAuthorizationFailure when denied or graph enforcement forbids SQL-only evidence
     */
    public OperationAuthorizationResponse preview(SessionAccess.Context context, UUID account, UUID organization,
            UUID group, String service, String operation) {
        return preview(context,account,organization,group,service,operation,false);
    }

    /**
     * Prepares legacy evidence while preserving the registered exact-resource admission contract.
     * @param context authenticated session context
     * @param account selected account ID
     * @param organization verified organization ID
     * @param group verified owning group, or null
     * @param service registered service ID
     * @param operation registered operation key
     * @param exactResourceAccess whether Document supplies a separately verified exact relationship
     * @return current SQL evidence without session activity writes
     * @throws OperationAuthorizationFailure when admission or current authority denies
     */
    OperationAuthorizationResponse preview(SessionAccess.Context context, UUID account, UUID organization,
            UUID group, String service, String operation, boolean exactResourceAccess) {
        return requireInternal(context,account,organization,group,service,operation,exactResourceAccess,false,null,false);
    }

    /**
     * Prepares current IAM admission and policy evidence before an external graph check.
     * @param context authenticated session context
     * @param account selected account ID
     * @param organization verified organization ID
     * @param group verified group scope, or null for the organization
     * @param service registered service ID
     * @param operation registered operation key
     * @return current admission and policy versions without an SQL authority decision
     * @throws OperationAuthorizationFailure when current IAM admission denies the operation
     */
    OperationAuthorizationResponse previewGraph(SessionAccess.Context context,UUID account,UUID organization,
            UUID group,String service,String operation) {
        return requireInternal(context,account,organization,group,service,operation,false,false,Set.of(),false);
    }

    /**
     * Rechecks IAM admission and policy using authority IDs proved by one pinned graph decision.
     * @param context authenticated session context
     * @param account selected account ID
     * @param organization verified organization ID
     * @param group verified group scope, or null for the organization
     * @param service registered service ID
     * @param operation registered operation key
     * @param graphAuthorities authority IDs matched at both graph layers
     * @return current operation evidence after IAM revalidation
     * @throws OperationAuthorizationFailure when admission, policy, or graph witnesses deny
     */
    OperationAuthorizationResponse requireGraph(SessionAccess.Context context,UUID account,UUID organization,
            UUID group,String service,String operation,Set<UUID> graphAuthorities) {
        return requireInternal(context,account,organization,group,service,operation,false,true,
                Set.copyOf(graphAuthorities),true);
    }

    /**
     * Rechecks selected-account eligibility after the final scope lock waits.
     * @param context current locked session context
     * @param account selected account ID
     * @throws OperationAuthorizationFailure when the session, credential or grant is no longer usable
     */
    public void revalidateGrant(SessionAccess.Context context, UUID account) {
        Instant started = clock.instant();
        SessionAccountGrant grant = sessions.liveGrant(context.session(), account, started)
                .orElseThrow(ProfessionalAuthorizationService::denied);
        Instant checked = clock.instant();
        if (checked.isBefore(started) || !context.session().activeAt(checked)
                || !grant.activeAt(checked, grant.credentialVersion())) throw denied();
    }

    /**
     * Retains the selected authorization deadline through the final transaction's completion check.
     * @param context locked session context
     * @param account selected account, which may differ from the context's sustaining grant
     * @param nextBoundary earliest scheduled projection transition, or null when none exists
     * @throws OperationAuthorizationFailure when eligibility expires before completion
     * @throws IllegalStateException when no synchronized SQL transaction is active
     */
    public void guardTransactionCompletion(SessionAccess.Context context, UUID account, Instant nextBoundary) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.isSynchronizationActive()) {
            throw new IllegalStateException("Authorization completion checks require a synchronized SQL transaction.");
        }
        Instant started = clock.instant();
        SessionAccountGrant selected = sessions.liveGrant(context.session(), account, started)
                .orElseThrow(ProfessionalAuthorizationService::denied);
        requireCompletionTime(context, selected, started, nextBoundary);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            /**
             * Rejects expiry during domain SQL work so its business, audit and outbox writes roll back together.
             * @param readOnly whether this transaction is read-only
             * @throws OperationAuthorizationFailure when the captured authorization deadline has passed
             */
            @Override
            public void beforeCommit(boolean readOnly) {
                // Re-evaluating policy here would incorrectly reject a command's own authorized ACL mutation.
                requireCompletionTime(context, selected, started, nextBoundary);
            }
        });
    }

    /**
     * Checks captured eligibility deadlines without database or remote calls after domain work.
     * @param context locked session context
     * @param selected current selected-account grant captured before domain work
     * @param started earliest accepted completion-check time
     * @param nextBoundary earliest scheduled projection transition, or null
     * @throws OperationAuthorizationFailure when time regresses or any deadline is reached
     */
    private void requireCompletionTime(SessionAccess.Context context, SessionAccountGrant selected,
            Instant started, Instant nextBoundary) {
        Instant checked = clock.instant();
        if (checked.isBefore(started) || nextBoundary != null && !checked.isBefore(nextBoundary)) {
            throw new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE, "SPICEDB_AUTHORIZATION_UNAVAILABLE");
        }
        if (!context.session().activeAt(checked)
                || !selected.activeAt(checked, selected.credentialVersion())) throw denied();
    }

    /** Evaluates a current organization's configured operation for a member without borrowing the member's session.
     * @param organization verified organization
     * @param account eligible member account
     * @param group optional managed group scope
     * @param service registered service
     * @param operation registered operation key
     * @return whether current policy and membership permit the operation
     */
    public boolean previewTarget(UUID organization,UUID account,UUID group,String service,String operation) {
        if(!professional(organization))throw denied();
        List<UUID> members=jdbc.query("""
                SELECT m.id FROM organization_membership m JOIN user_account a ON a.id=m.account_id
                JOIN users u ON u.id=a.user_id AND u.status='ACTIVE'
                JOIN organization o ON o.id=m.organization_id AND o.status='ACTIVE'
                WHERE m.organization_id=? AND m.account_id=? AND m.status='ACTIVE'
                AND a.organization_id=o.id AND a.type=o.type AND a.type IN('COMPANY','CUSTOM') AND a.status='ACTIVE'
                AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=o.id
                    AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED','PURGED')) FOR SHARE
                """,(row,index)->id(row.getBytes(1)),bytes(organization),bytes(account));
        if(members.size()!=1)throw denied();
        OperationPolicySnapshot snapshot=policies.findCurrent(service,operation,"ORGANIZATION")
                .orElseThrow(ProfessionalAuthorizationService::denied);
        Instant now=clock.instant();
        OperationAuthorityEvidence evidence=evidence(account,organization,group,members.getFirst(),snapshot.operationId(),now,false);
        OperationAuthorityPolicy policy=new OperationAuthorityPolicy(snapshot.policy().requiredAuthorityIds(),snapshot.policy().matchMode(),true);
        boolean allowed=policy.matches(evidenceWithCategory(evidence,snapshot));
        currentTime(account,organization,Set.of(snapshot.operationId()),now);
        return allowed;
    }

    private OperationAuthorizationResponse requireInternal(SessionAccess.Context context,UUID account,UUID organization,
            UUID group,String service,String operation,boolean exactResourceAccess,boolean recordActivity,
            Set<UUID> graphAuthorities,boolean graphProofRequired) {
        if (graphAuthorities == null && "auth-service".equals(service) && canaries != null) {
            ProfessionalSpiceDbCanary canary = canaries.getIfAvailable();
            // A direct facade call must not recover a SQL allow that the selected entry point forbids.
            if (canary != null) canary.requireDecision(organization,group,operation,null);
        }
        if(exactResourceAccess && (!service.equals("document-service") || !Set.of("file.read","file.download","file.copy","file.edit","file.collaborative.edit","folder.read","folder.copy").contains(operation))) throw denied();
        Instant now=clock.instant();
        SessionAccountGrant grant=sessions.liveGrant(context.session(),account,now).orElseThrow(ProfessionalAuthorizationService::denied);
        if((service.equals("auth-service") || operation.startsWith("organization.") || operation.equals("publication.approve") || operation.equals("publication.reject"))
                && !Set.of("LOGIN","PASSWORD").contains(grant.authMethod())) throw denied();
        if(!professional(organization)) throw denied();
        Long revision=jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR SHARE",Long.class);
        if(revision==null) throw denied();
        List<UUID> actors=jdbc.query("SELECT a.id FROM user_account a JOIN organization o ON o.id=a.organization_id WHERE a.id=? AND a.user_id=? AND a.organization_id=? AND a.status='ACTIVE' AND a.type=o.type AND a.type IN('COMPANY','CUSTOM') FOR SHARE",
                (row,index)->id(row.getBytes(1)),bytes(account),bytes(context.owner().userId()),bytes(organization));
        if(actors.size()!=1) throw denied();
        OrganizationRepository.Visibility membership=organizations.visibility(account,grant.authMethod(),organization).orElseThrow(ProfessionalAuthorizationService::denied);
        now=clock.instant();
        sessions.liveGrant(context.session(),account,now).orElseThrow(ProfessionalAuthorizationService::denied);
        OperationPolicySnapshot snapshot=policies.findCurrent(service,operation,"ORGANIZATION").orElseThrow(ProfessionalAuthorizationService::denied);
        OperationAuthorityPolicy policy=new OperationAuthorityPolicy(snapshot.policy().requiredAuthorityIds(),snapshot.policy().matchMode(),true);
        OperationAuthorityEvidence evidence=null;
        if(graphAuthorities==null) {
            evidence=evidence(account,organization,group,membership.membershipId(),snapshot.operationId(),now,exactResourceAccess);
            if(!policy.matches(evidenceWithCategory(evidence,snapshot))) throw denied();
        } else if(graphProofRequired && !policy.matches(new OperationAuthorityEvidence(
                snapshot.categoryAuthorityIds(),graphAuthorities,true,false))) throw denied();
        Map<UUID,String> keys=new HashMap<>();
        jdbc.query("SELECT a.id,a.authority_key FROM iam_policy_authority p JOIN iam_authority a ON a.id=p.authority_id WHERE p.policy_id=?",
                row->{keys.put(id(row.getBytes(1)),row.getString(2));},bytes(snapshot.policyId()));
        Set<String> required=new HashSet<>(); Set<String> category=new HashSet<>();
        for(UUID authority:snapshot.policy().requiredAuthorityIds()) {
            if(!keys.containsKey(authority)) throw denied();
            required.add(keys.get(authority));
            if(snapshot.categoryAuthorityIds().contains(authority) && (graphAuthorities==null
                    ? evidence.scopedAuthorityIds().contains(authority) : graphAuthorities.contains(authority))) category.add(keys.get(authority));
        }
        Instant checked=currentTime(account,organization,Set.of(snapshot.operationId()),now);
        if(!context.session().activeAt(checked) || !grant.activeAt(checked,grant.credentialVersion())) throw denied();
        if(recordActivity) sessions.touch(context.session(),grant,checked);
        return new OperationAuthorizationResponse(account,context.owner().userId(),context.session().id(),snapshot.operationId(),operation,
                "ORGANIZATION",snapshot.policyId(),policy.matchMode(),required,category,snapshot.operationVersion(),snapshot.policyVersion(),
                snapshot.categoryBindingVersion(),snapshot.categoryRoleVersion(),revision,snapshot.authorityVersions(),checked,checked,"ALLOWED");
    }

    /** Recipient eligibility grants neither a session nor membership and contains no private resource data. */
    public UUID recipient(UUID organization,UUID group,UUID recipient,String accessMode) {
        if(!Set.of("VIEW","EDIT").contains(accessMode)) throw denied();
        Instant now=clock.instant();
        jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR SHARE",Long.class);
        List<UUID> users=jdbc.query("""
                SELECT a.user_id FROM user_account a JOIN users u ON u.id=a.user_id AND u.status='ACTIVE'
                JOIN organization o ON o.id=a.organization_id AND o.status='ACTIVE'
                JOIN account_group_member m ON m.account_id=a.id AND m.status='LINKED'
                JOIN account_group g ON g.id=m.account_group_id AND g.user_id=a.user_id AND g.status='ACTIVE'
                WHERE a.id=? AND a.organization_id=? AND a.type=o.type AND a.type IN('COMPANY','CUSTOM') AND a.status='ACTIVE' FOR SHARE
                """,(row,index)->id(row.getBytes(1)),bytes(recipient),bytes(organization));
        if(users.size()!=1) throw denied();
        OrganizationRepository.Visibility member=organizations.visibility(recipient,"PASSWORD",organization).orElseThrow(ProfessionalAuthorizationService::denied);
        now=clock.instant();
        Set<UUID> operations=new HashSet<>();
        for(String operation:"EDIT".equals(accessMode)?List.of("file.read","file.collaborative.edit"):List.of("file.read")) {
            OperationPolicySnapshot snapshot=policies.findCurrent("document-service",operation,"ORGANIZATION").orElseThrow(ProfessionalAuthorizationService::denied);
            operations.add(snapshot.operationId());
            OperationAuthorityEvidence evidence=evidence(recipient,organization,group,member.membershipId(),snapshot.operationId(),now,true);
            if(!new OperationAuthorityPolicy(snapshot.policy().requiredAuthorityIds(),snapshot.policy().matchMode(),true).matches(evidenceWithCategory(evidence,snapshot))) throw denied();
        }
        currentTime(recipient,organization,operations,now);
        return users.getFirst();
    }

    /** A wall-clock transition during lock/SQL waits invalidates the entire computed view, even without a write. */
    private Instant currentTime(UUID account,UUID organization,Set<UUID> operations,Instant started) {
        Map<String,Object> parameters=Map.of("account",bytes(account),"org",bytes(organization),"operations",operations.stream().map(SessionRepository::bytes).toList(),"started",Timestamp.from(started));
        Instant boundary=new org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate(jdbc).query("""
                SELECT MIN(boundary) FROM (
                  SELECT valid_from boundary FROM iam_professional_assignment WHERE organization_id=:org AND account_id=:account AND status='ACTIVE' AND valid_from>:started
                  UNION ALL SELECT valid_until FROM iam_professional_assignment WHERE organization_id=:org AND account_id=:account AND status='ACTIVE' AND valid_until>:started
                  UNION ALL SELECT valid_from FROM group_membership WHERE organization_id=:org AND account_id=:account AND status='ACTIVE' AND valid_from>:started
                  UNION ALL SELECT valid_until FROM group_membership WHERE organization_id=:org AND account_id=:account AND status='ACTIVE' AND valid_until>:started
                  UNION ALL SELECT valid_from FROM iam_professional_restriction WHERE organization_id=:org AND operation_id IN(:operations) AND (account_id IS NULL OR account_id=:account) AND status='ACTIVE' AND valid_from>:started
                  UNION ALL SELECT valid_until FROM iam_professional_restriction WHERE organization_id=:org AND operation_id IN(:operations) AND (account_id IS NULL OR account_id=:account) AND status='ACTIVE' AND valid_until>:started
                  UNION ALL SELECT valid_from FROM iam_operation_restriction WHERE category_key='ORGANIZATION' AND operation_id IN(:operations) AND (account_id IS NULL OR account_id=:account) AND status='ACTIVE' AND valid_from>:started
                  UNION ALL SELECT valid_until FROM iam_operation_restriction WHERE category_key='ORGANIZATION' AND operation_id IN(:operations) AND (account_id IS NULL OR account_id=:account) AND status='ACTIVE' AND valid_until>:started
                ) transitions
                """,parameters,(java.sql.ResultSet result)->{if(!result.next()) return null;Timestamp value=result.getTimestamp(1);return value==null?null:value.toInstant();});
        Instant checked=clock.instant();
        if(checked.isBefore(started) || boundary!=null && !checked.isBefore(boundary)) throw denied();
        return checked;
    }

    /**
     * Checks the current recipient against complete authority witnesses at one legacy management scope.
     * @param context current session context
     * @param actor selected administrator account
     * @param organization verified organization
     * @param group target group
     * @param target recipient account
     * @throws OperationAuthorizationFailure when the recipient is outside the actor's eligible scope
     */
    public void assignmentRecipient(SessionAccess.Context context,UUID actor,UUID organization,UUID group,UUID target) {
        assignmentRecipient(context,actor,organization,group,target,"organization.group.assign");
    }

    /**
     * Checks recipient eligibility and complete authority witnesses at one scope for the actor's operation.
     * @param context current session context
     * @param actor selected administrator account
     * @param organization verified organization
     * @param group target group
     * @param target recipient account
     * @param operation registered group or department assignment operation
     * @throws OperationAuthorizationFailure when the recipient is outside the actor's eligible scope
     */
    public void assignmentRecipient(SessionAccess.Context context,UUID actor,UUID organization,UUID group,UUID target,
            String operation) {
        Instant now=clock.instant();
        List<UUID> members=jdbc.query("""
                SELECT m.id FROM organization_membership m
                JOIN organization o ON o.id=m.organization_id AND o.status='ACTIVE'
                JOIN user_account a ON a.id=m.account_id AND a.status='ACTIVE' AND a.organization_id=m.organization_id
                  AND a.type=o.type AND a.type IN('COMPANY','CUSTOM')
                JOIN users u ON u.id=a.user_id AND u.status='ACTIVE'
                WHERE m.organization_id=? AND m.account_id=? AND m.status='ACTIVE'
                  AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=m.organization_id
                    AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED','PURGED')) FOR SHARE
                """,
                (row,index)->id(row.getBytes(1)),bytes(organization),bytes(target));
        if(members.size()!=1) throw denied();
        Set<UUID> ancestry=ancestors(organization,group);
        String type=jdbc.queryForObject("SELECT type FROM iam_group WHERE organization_id=? AND id=? AND status='ACTIVE'",String.class,bytes(organization),bytes(group));
        if ("TEAM".equals(type) && !Set.of("organization.group.assign","organization.group.unassign").contains(operation)
                || "DEPARTMENT".equals(type) && !"organization.department.assign".equals(operation)
                || type==null || !Set.of("DEPARTMENT","TEAM").contains(type)) throw denied();
        OperationPolicySnapshot snapshot=policies.findCurrent("auth-service",operation,"ORGANIZATION")
                .orElseThrow(ProfessionalAuthorizationService::denied);
        List<AssignmentScope> scopes=jdbc.query("""
                SELECT a.group_id,p.scope_kind,a.role_id FROM iam_professional_assignment a
                JOIN iam_professional_responsibility p ON p.role_id=a.role_id
                JOIN iam_role r ON r.id=a.role_id AND r.status='ACTIVE'
                JOIN organization_membership m ON m.id=a.membership_id AND m.account_id=a.account_id
                  AND m.organization_id=a.organization_id AND m.status='ACTIVE'
                LEFT JOIN iam_group g ON g.id=a.group_id AND g.organization_id=a.organization_id
                  AND g.workspace_context='ORGANIZATION' AND g.status='ACTIVE'
                WHERE a.organization_id=? AND a.account_id=? AND a.status='ACTIVE'
                AND ((a.group_id IS NULL AND p.scope_kind='ORGANIZATION') OR p.scope_kind=CASE
                  WHEN g.type='DEPARTMENT' THEN 'DEPARTMENT' WHEN g.type IN('TEAM','PROJECT','CUSTOM') THEN 'TEAM' END)
                AND a.valid_from<=? AND (a.valid_until IS NULL OR a.valid_until>?) FOR SHARE
                """,(row,index)->new AssignmentScope(nullable(row.getBytes(1)),row.getString(2),id(row.getBytes(3))),bytes(organization),bytes(actor),Timestamp.from(now),Timestamp.from(now));
        Map<UUID,Set<UUID>> authoritiesByScope=new HashMap<>();
        for(AssignmentScope scope:scopes) {
            boolean orgAdmin=scope.group()==null && scope.kind().equals("ORGANIZATION");
            boolean departmentAdmin=scope.kind().equals("DEPARTMENT") && ancestry.contains(scope.group()) && groupMember(organization,scope.group(),actor,now)
                    && groupMember(organization,scope.group(),target,now);
            if(!orgAdmin && !departmentAdmin) continue;
            UUID managedScope=scope.group()==null?organization:scope.group();
            authoritiesByScope.computeIfAbsent(managedScope,key->new HashSet<>()).addAll(jdbc.query(
                    "SELECT ra.authority_id FROM iam_role_authority ra JOIN iam_authority a ON a.id=ra.authority_id AND a.status='ACTIVE' WHERE ra.role_id=?",
                    (row,index)->id(row.getBytes(1)),bytes(scope.role())));
        }
        OperationAuthorityPolicy policy=new OperationAuthorityPolicy(snapshot.policy().requiredAuthorityIds(),snapshot.policy().matchMode(),true);
        // ALL_OF cannot borrow missing authorities from another department or the organization scope.
        if(authoritiesByScope.values().stream().noneMatch(authorities->policy.matches(
                new OperationAuthorityEvidence(snapshot.categoryAuthorityIds(),authorities,true,false)))) throw denied();
        currentTime(actor,organization,Set.of(snapshot.operationId()),now);
        currentTime(target,organization,Set.of(snapshot.operationId()),now);
    }

    /**
     * Requires a coherent scope membership that remains valid after its row locks are acquired.
     * @param organization verified tenant
     * @param group required owning scope
     * @param account target account
     * @throws OperationAuthorizationFailure when membership is absent, unavailable or expired
     */
    public void requireScopeMember(UUID organization,UUID group,UUID account) {
        if(!groupMember(organization,group,account,clock.instant())) throw denied();
    }

    /**
     * Builds legacy authority evidence from eligible responsibilities in the verified owning branch.
     * @param account selected actor or target account
     * @param organization verified tenant
     * @param group owning group, or null for organization scope
     * @param membership current organization-membership identity
     * @param operation registered operation identifier
     * @param now eligibility evaluation time
     * @param exactResourceAccess whether separate resource checks replace the direct group-membership requirement
     * @return current scoped authorities and applicable explicit-deny state
     * @throws OperationAuthorizationFailure when group admission or ancestry is invalid
     */
    private OperationAuthorityEvidence evidence(UUID account,UUID organization,UUID group,UUID membership,UUID operation,Instant now,boolean exactResourceAccess) {
        Set<UUID> ancestry=ancestors(organization,group);
        Set<UUID> scoped=new HashSet<>();
        // Developer-managed baseline is separate from the category ceiling and scoped responsibilities.
        jdbc.query("SELECT ra.authority_id FROM iam_context_member_role_binding b JOIN iam_role r ON r.id=b.role_id AND r.status='ACTIVE' JOIN iam_role_authority ra ON ra.role_id=r.id WHERE b.category_key='ORGANIZATION' AND b.status='ACTIVE'",
                row->{scoped.add(id(row.getBytes(1)));});
        List<RoleScope> roles=jdbc.query("""
                SELECT a.role_id,a.group_id FROM iam_professional_assignment a
                JOIN iam_role r ON r.id=a.role_id AND r.status='ACTIVE'
                JOIN iam_professional_responsibility p ON p.role_id=a.role_id
                LEFT JOIN iam_group g ON g.id=a.group_id AND g.organization_id=a.organization_id
                  AND g.workspace_context='ORGANIZATION' AND g.status='ACTIVE'
                WHERE a.organization_id=? AND a.membership_id=? AND a.account_id=? AND a.status='ACTIVE'
                AND ((a.group_id IS NULL AND p.scope_kind='ORGANIZATION') OR p.scope_kind=CASE
                  WHEN g.type='DEPARTMENT' THEN 'DEPARTMENT' WHEN g.type IN('TEAM','PROJECT','CUSTOM') THEN 'TEAM' END)
                AND a.valid_from<=? AND (a.valid_until IS NULL OR a.valid_until>?) FOR SHARE
                """,(row,index)->new RoleScope(id(row.getBytes(1)),nullable(row.getBytes(2))),bytes(organization),bytes(membership),bytes(account),Timestamp.from(now),Timestamp.from(now));
        boolean scopeManager=false;
        Set<UUID> requirements=new HashSet<>(jdbc.query("SELECT pa.authority_id FROM iam_policy_authority pa JOIN iam_operation_policy p ON p.id=pa.policy_id WHERE p.operation_id=?",(row,index)->id(row.getBytes(1)),bytes(operation)));
        for(RoleScope role:roles) {
            if(role.group()!=null && !ancestry.contains(role.group())) continue;
            if(role.group()!=null && !groupMember(organization,role.group(),account,now)) continue;
            List<UUID> authorities=jdbc.query("SELECT authority_id FROM iam_role_authority WHERE role_id=?",(row,index)->id(row.getBytes(1)),bytes(role.role()));
            if(authorities.stream().anyMatch(requirements::contains)) scopeManager=true;
            scoped.addAll(authorities);
        }
        if(group!=null && !exactResourceAccess && !scopeManager && !groupMember(organization,group,account,now)) throw denied();
        List<Restriction> restrictions=jdbc.query("""
                SELECT group_id FROM iam_professional_restriction WHERE organization_id=? AND operation_id=?
                AND (account_id IS NULL OR account_id=?) AND status='ACTIVE' AND valid_from<=?
                AND (valid_until IS NULL OR valid_until>?) FOR SHARE
                """,(row,index)->new Restriction(nullable(row.getBytes(1))),bytes(organization),bytes(operation),bytes(account),Timestamp.from(now),Timestamp.from(now));
        boolean deny=restrictions.stream().anyMatch(value->value.group()==null || ancestry.contains(value.group()));
        boolean platformDeny=Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_operation_restriction WHERE operation_id=? AND category_key='ORGANIZATION' AND (account_id IS NULL OR account_id=?) AND status='ACTIVE' AND valid_from<=? AND (valid_until IS NULL OR valid_until>?))",Boolean.class,bytes(operation),bytes(account),Timestamp.from(now),Timestamp.from(now)));
        return new OperationAuthorityEvidence(Set.of(),scoped,true,deny||platformDeny);
    }
    private static OperationAuthorityEvidence evidenceWithCategory(OperationAuthorityEvidence evidence,OperationPolicySnapshot snapshot) {
        return new OperationAuthorityEvidence(snapshot.categoryAuthorityIds(),evidence.scopedAuthorityIds(),evidence.currentCoherent(),evidence.applicableExplicitDeny());
    }

    public Set<UUID> ancestors(UUID organization,UUID group) {
        Set<UUID> ids=new HashSet<>(); UUID cursor=group;
        while(cursor!=null) {
            if(ids.size()>=32 || !ids.add(cursor)) throw denied();
            List<Parent> parents=jdbc.query("SELECT parent_group_id FROM iam_group WHERE id=? AND organization_id=? AND status='ACTIVE' AND workspace_context='ORGANIZATION' FOR SHARE",
                    (row,index)->new Parent(nullable(row.getBytes(1))),bytes(cursor),bytes(organization));
            if(parents.size()!=1) throw denied();
            cursor=parents.getFirst().id();
        }
        return Set.copyOf(ids);
    }
    /**
     * Locks a live group membership anchored to the account's current eligible organization membership.
     * @param organization verified tenant
     * @param group required owning scope
     * @param account actor or recipient account
     * @param now eligibility evaluation time
     * @return whether exactly one coherent membership remains current after any lock wait
     */
    private boolean groupMember(UUID organization,UUID group,UUID account,Instant now) {
        List<ScopeMembership> memberships=jdbc.query("""
                SELECT gm.valid_until FROM group_membership gm
                JOIN organization_membership m ON m.id=gm.organization_membership_id
                  AND m.organization_id=gm.organization_id AND m.account_id=gm.account_id AND m.status='ACTIVE'
                JOIN organization o ON o.id=gm.organization_id AND o.status='ACTIVE'
                JOIN user_account a ON a.id=gm.account_id AND a.organization_id=gm.organization_id
                  AND a.type=o.type AND a.status='ACTIVE'
                JOIN users u ON u.id=a.user_id AND u.status='ACTIVE'
                JOIN iam_group g ON g.id=gm.group_id AND g.organization_id=gm.organization_id
                  AND g.workspace_context='ORGANIZATION' AND g.status='ACTIVE'
                WHERE gm.organization_id=? AND gm.group_id=? AND gm.account_id=? AND gm.status='ACTIVE'
                  AND gm.valid_from<=? AND (gm.valid_until IS NULL OR gm.valid_until>?)
                  AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=gm.organization_id
                    AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED','PURGED')) FOR SHARE
                """,(row,index)->{
                    Timestamp until=row.getTimestamp(1);
                    return new ScopeMembership(until==null?null:until.toInstant());
                },bytes(organization),bytes(group),bytes(account),Timestamp.from(now),Timestamp.from(now));
        Instant checked=clock.instant();
        return memberships.size()==1 && !checked.isBefore(now)
                && (memberships.getFirst().validUntil()==null || checked.isBefore(memberships.getFirst().validUntil()));
    }
    private record ScopeMembership(Instant validUntil) { }
    private record Parent(UUID id) { }
    private record RoleScope(UUID role,UUID group) { }
    private record Restriction(UUID group) { }
    private record AssignmentScope(UUID group,String kind,UUID role) { }
    private static UUID nullable(byte[] value) { return value==null?null:id(value); }
    private static UUID id(byte[] value) { ByteBuffer b=ByteBuffer.wrap(value); return new UUID(b.getLong(),b.getLong()); }
    private static OperationAuthorizationFailure denied() { return new OperationAuthorizationFailure(HttpStatus.FORBIDDEN,"PROFESSIONAL_AUTHORITY_DENIED"); }
}
