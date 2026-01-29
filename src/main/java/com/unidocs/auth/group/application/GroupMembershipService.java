package com.unidocs.auth.group.application;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import jakarta.validation.Validator;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import com.unidocs.auth.group.api.GroupAssignmentRequest;
import com.unidocs.auth.group.api.GroupMembershipResponse;
import com.unidocs.auth.group.domain.GroupMembership;
import com.unidocs.auth.group.persistence.GroupMembershipRepository;
import com.unidocs.auth.group.persistence.GroupRepository;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;

@Service
@Transactional(propagation = Propagation.NEVER)
public class GroupMembershipService {
    public record Page(List<GroupMembershipResponse> memberships, UUID nextCursor) { }
    private record Mutation(GroupMembershipResponse response, long organizationVersion) { }
    private final GroupMembershipRepository members;
    private final GroupRepository groups;
    private final OrganizationRepository organizations;
    private final SessionRepository sessions;
    private final SessionAccess access;
    private final OutboxRepository outbox;
    private final OrganizationSnapshotStore snapshots;
    private final Validator validator;
    private final MeterRegistry metrics;
    private final com.unidocs.auth.group.persistence.GroupRuleRepository rules;
    private final com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional;
    private final com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary;

    @Autowired
    public GroupMembershipService(GroupMembershipRepository members, GroupRepository groups, OrganizationRepository organizations,
            SessionRepository sessions, SessionAccess access, OutboxRepository outbox, OrganizationSnapshotStore snapshots,
            Validator validator, MeterRegistry metrics, com.unidocs.auth.group.persistence.GroupRuleRepository rules,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional,
            ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> canaryProvider) {
        this(members,groups,organizations,sessions,access,outbox,snapshots,validator,metrics,rules,professional,canaryProvider.getIfAvailable());
    }
    public GroupMembershipService(GroupMembershipRepository members, GroupRepository groups, OrganizationRepository organizations,
            SessionRepository sessions, SessionAccess access, OutboxRepository outbox, OrganizationSnapshotStore snapshots,
            Validator validator, MeterRegistry metrics, com.unidocs.auth.group.persistence.GroupRuleRepository rules,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional) {
        this(members,groups,organizations,sessions,access,outbox,snapshots,validator,metrics,rules,professional,
                (com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary)null);
    }
    private GroupMembershipService(GroupMembershipRepository members, GroupRepository groups, OrganizationRepository organizations,
            SessionRepository sessions, SessionAccess access, OutboxRepository outbox, OrganizationSnapshotStore snapshots,
            Validator validator, MeterRegistry metrics, com.unidocs.auth.group.persistence.GroupRuleRepository rules,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary) {
        this.professional=professional;
        this.canary=canary;
        this.rules=rules; this.members = members; this.groups = groups; this.organizations = organizations; this.sessions = sessions;
        this.access = access; this.outbox = outbox; this.snapshots = snapshots; this.validator = validator; this.metrics = metrics;
    }
    /**
     * Assigns an eligible recipient only after command-bound graph and current scope revalidation.
     * @param sid authenticated session
     * @param subject authenticated login account
     * @param organization verified tenant
     * @param group target department or team
     * @param request validated assignment command
     * @return current assigned membership, including idempotent retries
     * @throws GroupFailure when command validation, recipient eligibility or legacy scope checks fail
     * @throws com.unidocs.auth.authorization.application.OperationAuthorizationFailure when graph evidence fails
     */
    public GroupMembershipResponse assign(UUID sid, UUID subject, UUID organization, UUID group, GroupAssignmentRequest request) {
        if (request == null || !validator.validate(request).isEmpty()) throw badRequest();
        String role;
        try { role = GroupMembership.normalizedRole(request.role()); }
        catch (IllegalArgumentException invalid) { throw badRequest(); }
        if ((request.validUntil() != null && !request.validUntil().isAfter(request.validFrom()))
                || !databaseTime(request.validFrom()) || (request.validUntil() != null && !databaseTime(request.validUntil()))) throw badRequest();
        String fingerprint = fingerprint(group, request, role);
        UUID targetGroup = members.accountGroup(request.memberAccountId()).orElseThrow(GroupMembershipService::denied);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision =
                checkAssignmentCanary(sid,subject,request.accountId(),organization,group,request.memberAccountId(),"organization.group.assign");
        try {
            Mutation result = access.executeForGroups(sid, subject, List.of(targetGroup), context -> {
                SessionAccountGrant grant = assignAuthority(context,request.accountId(),organization,group,"organization.group.assign",canaryDecision);
                if (canaryDecision != null) {
                    canary.requireAssignmentRecipient(canaryDecision, request.memberAccountId());
                    canary.revalidate(canaryDecision, context, request.accountId(), organization);
                }
                if(professional.professional(organization) && request.manageGroup()) throw badRequest();
                // Selected graph decisions already bind a direct responsibility and current actor/recipient scope.
                if(professional.professional(organization) && (canaryDecision==null || !canaryDecision.enforcing())) professionalRecipient(context,request.accountId(),organization,group,
                        request.memberAccountId(),assignmentOperation(organization,group,"organization.group.assign"));
                if (groups.find(organization, group).isEmpty()) throw denied();
                OrganizationRepository.Visibility target = organizations.visibility(request.memberAccountId(), "PASSWORD", organization).orElseThrow(GroupMembershipService::denied);
                if(rules.university(organization) && rules.student(target.membershipId()) && groups.find(organization,group).orElseThrow().group().type()==com.unidocs.auth.group.domain.Group.Type.COURSE) throw denied();
                GroupMembershipRepository.Assignment existing = members.assignment(organization, request.accountId(), request.requestId()).orElse(null);
                if (existing != null) {
                    if (!existing.fingerprint().equals(fingerprint) || !existing.membership().organizationMembershipId().equals(target.membershipId())) throw conflict();
                    sessions.touch(context.session(), grant, context.now());
                    return new Mutation(GroupMembershipResponse.from(existing.membership(), context.now(), true), 0);
                }
                if (request.validUntil() != null && !request.validUntil().isAfter(context.now())) throw badRequest();
                GroupMembership member = new GroupMembership(UUID.randomUUID(), organization, group, request.memberAccountId(), target.membershipId(),
                        role, request.validUntil() == null ? GroupMembership.MembershipType.PERMANENT : GroupMembership.MembershipType.TEMPORARY,
                        GroupMembership.Source.ORGANIZATION_ASSIGNMENT, null, GroupMembership.Status.ACTIVE, request.validFrom(), request.validUntil(),
                        1, context.now(), context.now(), request.manageGroup());
                members.create(member, request.accountId(), request.requestId(), fingerprint);
                member = members.find(organization, group, member.id()).orElseThrow();
                long version = changed(member, request.accountId(), context, "GROUP_MEMBER_ASSIGNED");
                sessions.touch(context.session(), grant, context.now());
                return new Mutation(GroupMembershipResponse.from(member, context.now(), true), version);
            });
            invalidate(organization, result.organizationVersion());
            metrics.counter("group.membership", "outcome", "assigned").increment();
            return result.response();
        } catch (DataIntegrityViolationException duplicate) { throw conflict(); }
    }
    /**
     * Revokes the selected membership using graph evidence bound to its current recipient.
     * @param sid authenticated session
     * @param subject authenticated login account
     * @param organization verified tenant
     * @param group owning department or team
     * @param membership membership being revoked
     * @param account selected administrator account
     * @return current revoked membership
     * @throws GroupFailure when admission or recipient scope checks fail
     * @throws com.unidocs.auth.authorization.application.OperationAuthorizationFailure when graph evidence fails
     */
    public GroupMembershipResponse revoke(UUID sid, UUID subject, UUID organization, UUID group, UUID membership, UUID account) {
        UUID target = members.memberAccount(organization, group, membership).orElseThrow(GroupMembershipService::denied);
        UUID targetGroup = members.accountGroup(target).orElseThrow(GroupMembershipService::denied);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision =
                checkAssignmentCanary(sid,subject,account,organization,group,target,"organization.group.unassign");
        Mutation result = access.executeForGroups(sid, subject, List.of(targetGroup), context -> {
            SessionAccountGrant grant = assignAuthority(context,account,organization,group,"organization.group.unassign",canaryDecision);
            if (canaryDecision != null) {
                canary.requireAssignmentRecipient(canaryDecision, target);
                canary.revalidate(canaryDecision, context, account, organization);
            }
            if(professional.professional(organization) && (canaryDecision==null || !canaryDecision.enforcing())) professionalRecipient(context,account,organization,group,target,
                    assignmentOperation(organization,group,"organization.group.unassign"));
            if (groups.find(organization, group).isEmpty()) throw denied();
            GroupMembership current = members.find(organization, group, membership).orElseThrow(GroupMembershipService::denied);
            if (!current.accountId().equals(target)) throw denied();
            long version = 0;
            if (current.status() == GroupMembership.Status.ACTIVE) {
                members.revoke(membership, account, context.now());
                current = members.find(organization, group, membership).orElseThrow();
                version = changed(current, account, context, "GROUP_MEMBER_REVOKED");
            }
            sessions.touch(context.session(), grant, context.now());
            return new Mutation(GroupMembershipResponse.from(current, context.now(), false), version);
        });
        invalidate(organization, result.organizationVersion());
        metrics.counter("group.membership", "outcome", "revoked").increment();
        return result.response();
    }
    public Page list(UUID sid, UUID subject, UUID account, UUID organization, UUID group, UUID after, int limit) {
        return page(sid, subject, account, organization, group, after, limit, true);
    }
    public Page mine(UUID sid, UUID subject, UUID account, UUID organization, UUID after, int limit) {
        return page(sid, subject, account, organization, null, after, limit, false);
    }
    private Page page(UUID sid, UUID subject, UUID account, UUID organization, UUID group, UUID after, int limit, boolean admin) {
        if (limit < 1 || limit > 100) throw badRequest();
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision = admin
                ? checkAssignmentCanary(sid,subject,account,organization,group,null,"organization.group.assign")
                : canary!=null && canary.applies(organization,"workspace.read")
                        ? canary.checkContent(sid,subject,account,organization,null,"workspace.read",false):null;
        return access.execute(sid, subject, context -> {
            SessionAccountGrant grant = admin && professional.professional(organization)
                    ? assignAuthority(context,account,organization,group,"organization.group.assign",canaryDecision)
                    : authorize(context, account, organization, false, admin,canaryDecision);
            if(canaryDecision!=null)canary.revalidate(canaryDecision,context,account,organization);
            if (admin && groups.find(organization, group).isEmpty()) throw denied();
            UUID anchor = admin ? null : organizations.visibility(account, grant.authMethod(), organization).orElseThrow(GroupMembershipService::denied).membershipId();
            List<GroupMembershipRepository.Row> rows = members.list(organization, group, anchor, after, limit + 1, context.now());
            List<GroupMembershipResponse> page = rows.stream().limit(limit)
                    .map(row -> GroupMembershipResponse.from(row.membership(), context.now(), row.organizationAvailable())).toList();
            sessions.touch(context.session(), grant, context.now());
            return new Page(page, rows.size() > limit ? page.getLast().id() : null);
        });
    }
    private SessionAccountGrant authorize(SessionAccess.Context context, UUID account, UUID organization, boolean mutation, boolean admin) {
        return authorize(context,account,organization,mutation,admin,null);
    }
    /**
     * Preserves current navigation admission and requires selected graph evidence before reading memberships.
     * @param context locked session context
     * @param account selected account
     * @param organization verified tenant
     * @param mutation whether mutation locks are required
     * @param admin whether administrator admission is required
     * @param decision request-local navigation evidence
     * @return current selected-account grant
     */
    private SessionAccountGrant authorize(SessionAccess.Context context, UUID account, UUID organization, boolean mutation, boolean admin,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision) {
        SessionAccountGrant grant = sessions.liveGrant(context.session(), account, context.now()).orElseThrow(GroupMembershipService::denied);
        if ((admin && !Set.of("LOGIN", "PASSWORD").contains(grant.authMethod())) || !groups.lockOrganization(organization, mutation)) throw denied();
        OrganizationRepository.Visibility visible = organizations.visibility(account, grant.authMethod(), organization).orElseThrow(GroupMembershipService::denied);
        if(organizations.university(organization)) throw denied();
        if(professional.professional(organization)) {
            if(canary!=null)canary.requireContentDecision(organization,null,"workspace.read",false,decision);
            professionalGrant(context,account,organization,null,"document-service","workspace.read");
            return grant;
        }
        if (admin && visible.role() != OrganizationMembership.Role.OWNER && visible.role() != OrganizationMembership.Role.ADMIN) throw denied();
        return grant;
    }
    private SessionAccountGrant assignAuthority(SessionAccess.Context context,UUID account,UUID org,UUID group,String operation,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision) {
        if(!professional.professional(org)) return authorize(context,account,org,true,true);
        operation=assignmentOperation(org,group,operation);
        if(canary!=null)canary.requireDecision(org,group,operation,decision);
        if(decision!=null && decision.enforcing()
                && (!operation.equals(decision.operation()) || !group.equals(decision.group()))) throw denied();
        if(decision==null || !decision.enforcing()) professionalGrant(context,account,org,group,"auth-service",operation);
        return sessions.liveGrant(context.session(),account,context.now()).orElseThrow(GroupMembershipService::denied);
    }
    private void professionalGrant(SessionAccess.Context context,UUID account,UUID org,UUID group,String service,String operation) {
        try { professional.require(context,account,org,group,service,operation); }
        catch(com.unidocs.auth.authorization.application.OperationAuthorizationFailure failure) { throw new GroupFailure(failure.status()); }
    }
    private void professionalRecipient(SessionAccess.Context context,UUID account,UUID org,UUID group,UUID target,String operation) {
        try { professional.assignmentRecipient(context,account,org,group,target,operation); }
        catch(com.unidocs.auth.authorization.application.OperationAuthorizationFailure failure) { throw new GroupFailure(failure.status()); }
    }
    private String groupType(UUID org,UUID group) {
        return groups.find(org,group).orElseThrow(GroupMembershipService::denied).group().type().name();
    }
    private String assignmentOperation(UUID organization, UUID group, String operation) {
        String type=groupType(organization,group);
        if("DEPARTMENT".equals(type)) return "organization.department.assign";
        if(!"TEAM".equals(type)) throw denied();
        return operation;
    }
    private com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision checkAssignmentCanary(
            UUID sid,UUID subject,UUID account,UUID organization,UUID group,UUID recipient,String operation) {
        if(canary==null || !canary.applies(organization,"organization.department.assign")
                && !canary.applies(organization,operation))return null;
        String selected=assignmentOperation(organization,group,operation);
        return canary.applies(organization,selected)
                ? recipient == null ? canary.check(sid,subject,account,organization,group,selected)
                        : canary.checkAssignment(sid,subject,account,organization,group,recipient,selected):null;
    }
    private long changed(GroupMembership member, UUID actor, SessionAccess.Context context, String event) {
        long version = members.advanceOrganization(member.organizationId(), context.now());
        sessions.audit(context.owner().userId(), actor, context.session().id(), event, context.now());
        outbox.groupMembershipChanged(member, version, event, context.now());
        return version;
    }
    private void invalidate(UUID organization, long version) {
        if (version == 0) return;
        try { snapshots.invalidate(organization, version); }
        catch (RuntimeException unavailable) { metrics.counter("group.membership", "outcome", "cache_invalidation_failed").increment(); }
    }
    private static boolean databaseTime(java.time.Instant instant) {
        return instant.getNano() % 1000 == 0 && !instant.isBefore(java.time.Instant.parse("1000-01-01T00:00:00Z"))
                && instant.isBefore(java.time.Instant.parse("+10000-01-01T00:00:00Z"));
    }
    private static GroupFailure denied() { return new GroupFailure(HttpStatus.FORBIDDEN); }
    private static GroupFailure badRequest() { return new GroupFailure(HttpStatus.BAD_REQUEST); }
    private static GroupFailure conflict() { return new GroupFailure(HttpStatus.CONFLICT); }
    private static String fingerprint(UUID group, GroupAssignmentRequest request, String role) {
        String canonical = group + "\n" + request.memberAccountId() + "\n" + role + "\n" + request.validFrom() + "\n" + request.validUntil() + (request.manageGroup()?"\nMANAGE_GROUP":"");
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException unavailable) { throw new IllegalStateException(unavailable); }
    }
}
