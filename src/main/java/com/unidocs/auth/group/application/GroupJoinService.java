package com.unidocs.auth.group.application;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import jakarta.validation.Validator;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import com.unidocs.auth.group.api.GroupJoinRequests;
import com.unidocs.auth.group.api.GroupJoinResponse;
import com.unidocs.auth.group.domain.GroupJoinRequest;
import com.unidocs.auth.group.domain.GroupMembership;
import com.unidocs.auth.group.persistence.GroupJoinRepository;
import com.unidocs.auth.group.persistence.GroupMembershipRepository;
import com.unidocs.auth.group.persistence.GroupRepository;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;

@Service
@Transactional(propagation=Propagation.NEVER)
public class GroupJoinService {
    public record Page(List<GroupJoinResponse> requests, UUID nextCursor) { }
    private record Decision(GroupJoinResponse response,long organizationVersion) { }
    private final GroupJoinRepository requests;
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
    private final GroupAuthority authority;

    public GroupJoinService(GroupJoinRepository requests,GroupMembershipRepository members,GroupRepository groups,OrganizationRepository organizations,
            SessionRepository sessions,SessionAccess access,OutboxRepository outbox,OrganizationSnapshotStore snapshots,Validator validator,MeterRegistry metrics,com.unidocs.auth.group.persistence.GroupRuleRepository rules,GroupAuthority authority) {
        this.rules=rules;this.authority=authority;this.requests=requests;this.members=members;this.groups=groups;this.organizations=organizations;this.sessions=sessions;this.access=access;
        this.outbox=outbox;this.snapshots=snapshots;this.validator=validator;this.metrics=metrics;
    }
    public GroupJoinResponse submit(UUID sid,UUID subject,UUID organization,UUID group,GroupJoinRequests.Submit command) {
        if(command==null || !validator.validate(command).isEmpty()) throw badRequest();
        String role=role(command.requestedRole());
        String reason=reason(command.reason());
        String fingerprint=hash(group+"\n"+role+"\n"+reason);
        try {
            return access.execute(sid,subject,context->{
                SessionAccountGrant grant=authorize(context,command.accountId(),organization,false);
                if(!rules.university(organization)) throw denied();
                OrganizationRepository.Visibility visible=organizations.visibility(command.accountId(),grant.authMethod(),organization).orElseThrow(GroupJoinService::denied);
                if(groups.find(organization,group).isEmpty()) throw denied();
                requireApproval(organization,group,visible.membershipId(),context.now());
                GroupJoinRepository.Stored retry=requests.retry(organization,command.accountId(),command.requestId()).orElse(null);
                if(retry!=null) {
                    if(!fingerprint.equals(retry.creationFingerprint()) || !retry.request().organizationMembershipId().equals(visible.membershipId())) throw conflict();
                    sessions.touch(context.session(),grant,context.now());
                    return GroupJoinResponse.from(retry.request());
                }
                if(members.hasActiveAssignment(group,visible.membershipId())) throw conflict();
                UUID id=UUID.randomUUID();
                requests.create(id,organization,group,command.accountId(),visible.membershipId(),command.requestId(),fingerprint,role,reason,context.now());
                GroupJoinRequest created=requests.find(organization,group,id).orElseThrow().request();
                changed(created,context,command.accountId(),"GROUP_JOIN_REQUESTED");
                sessions.touch(context.session(),grant,context.now());
                return GroupJoinResponse.from(created);
            });
        } catch(DataIntegrityViolationException duplicate) { throw conflict(); }
    }
    public GroupJoinResponse review(UUID sid,UUID subject,UUID organization,UUID group,UUID id,GroupJoinRequests.Review command) {
        if(command==null || !validator.validate(command).isEmpty()) throw badRequest();
        String reviewReason=reason(command.reason());
        String approvedRole=command.approve()?role(command.role()):null;
        if(command.approve()) {
            if(!databaseTime(command.validFrom()) || (command.validUntil()!=null && (!databaseTime(command.validUntil()) || !command.validUntil().isAfter(command.validFrom())))) throw badRequest();
        } else if(command.role()!=null || command.validFrom()!=null || command.validUntil()!=null) throw badRequest();
        String fingerprint=hash(command.approve()+"\n"+approvedRole+"\n"+command.validFrom()+"\n"+command.validUntil()+"\n"+reviewReason);
        GroupJoinRequest original=requests.find(organization,group,id).orElseThrow(GroupJoinService::denied).request();
        UUID targetGroup=members.accountGroup(original.accountId()).orElseThrow(GroupJoinService::denied);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision=
                authority.checkManagerCanary(sid,subject,command.accountId(),organization,group);
        try {
            Decision result=access.executeForGroups(sid,subject,List.of(targetGroup),context->{
                SessionAccountGrant grant=authority.require(context,command.accountId(),organization,group,true,true,false,command.approve(),canaryDecision).grant();
                if(command.approve() && !rules.university(organization)) throw denied();
                GroupJoinRepository.Stored stored=requests.find(organization,group,id).orElseThrow(GroupJoinService::denied);
                GroupJoinRequest current=stored.request();
                UUID actorGroup=members.accountGroup(command.accountId()).orElseThrow(GroupJoinService::denied);
                if(actorGroup.equals(targetGroup)) throw denied();
                if(current.status()!=GroupJoinRequest.Status.PENDING) {
                    if(!command.accountId().equals(current.reviewedBy()) || !fingerprint.equals(stored.reviewFingerprint())) throw conflict();
                    sessions.touch(context.session(),grant,context.now());
                    return new Decision(GroupJoinResponse.from(current),0);
                }
                UUID membershipId=null;
                long organizationVersion=0;
                if(command.approve()) {
                    if(groups.find(organization,group).isEmpty()) throw denied();
                    OrganizationRepository.Visibility target=organizations.visibility(current.accountId(),"PASSWORD",organization).orElseThrow(GroupJoinService::denied);
                    requireApproval(organization,group,target.membershipId(),context.now());
                    if(!target.membershipId().equals(current.organizationMembershipId())) throw denied();
                    if(command.validUntil()!=null && !command.validUntil().isAfter(context.now())) throw badRequest();
                    if(members.hasActiveAssignment(group,target.membershipId())) throw conflict();
                    GroupMembership membership=new GroupMembership(UUID.randomUUID(),organization,group,current.accountId(),target.membershipId(),approvedRole,
                            command.validUntil()==null?GroupMembership.MembershipType.PERMANENT:GroupMembership.MembershipType.TEMPORARY,
                            GroupMembership.Source.ADMIN_APPROVAL,id.toString(),GroupMembership.Status.ACTIVE,command.validFrom(),command.validUntil(),1,context.now(),context.now());
                    members.create(membership,command.accountId(),id,fingerprint);
                    membershipId=membership.id();
                    organizationVersion=members.advanceOrganization(organization,context.now());
                    sessions.audit(context.owner().userId(),command.accountId(),sid,"GROUP_MEMBER_ASSIGNED",context.now());
                    outbox.groupMembershipChanged(membership,organizationVersion,"GROUP_MEMBER_ASSIGNED",context.now());
                }
                requests.review(id,command.approve(),command.accountId(),reviewReason,fingerprint,membershipId,context.now());
                GroupJoinRequest reviewed=requests.find(organization,group,id).orElseThrow().request();
                changed(reviewed,context,command.accountId(),command.approve()?"GROUP_JOIN_APPROVED":"GROUP_JOIN_REJECTED");
                sessions.touch(context.session(),grant,context.now());
                return new Decision(GroupJoinResponse.from(reviewed),organizationVersion);
            });
            if(result.organizationVersion()>0) {
                try { snapshots.invalidate(organization,result.organizationVersion()); }
                catch(RuntimeException unavailable) { metrics.counter("group.join","outcome","cache_invalidation_failed").increment(); }
            }
            return result.response();
        } catch(DataIntegrityViolationException duplicate) { throw conflict(); }
    }
    public GroupJoinResponse cancel(UUID sid,UUID subject,UUID organization,UUID group,UUID id,UUID account) {
        return access.execute(sid,subject,context->{
            SessionAccountGrant grant=authorize(context,account,organization,false);
            OrganizationRepository.Visibility visible=organizations.visibility(account,grant.authMethod(),organization).orElseThrow(GroupJoinService::denied);
            GroupJoinRequest current=requests.find(organization,group,id).orElseThrow(GroupJoinService::denied).request();
            if(!current.accountId().equals(account) || !current.organizationMembershipId().equals(visible.membershipId())) throw denied();
            if(current.status()==GroupJoinRequest.Status.PENDING) {
                requests.cancel(id,context.now());current=requests.find(organization,group,id).orElseThrow().request();
                changed(current,context,account,"GROUP_JOIN_CANCELLED");
            } else if(current.status()!=GroupJoinRequest.Status.CANCELLED) throw conflict();
            sessions.touch(context.session(),grant,context.now());
            return GroupJoinResponse.from(current);
        });
    }
    public Page list(UUID sid,UUID subject,UUID account,UUID organization,UUID group,GroupJoinRequest.Status status,UUID after,int limit,boolean admin) {
        if(limit<1 || limit>100) throw badRequest();
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision=admin
                ? authority.checkManagerCanary(sid,subject,account,organization,group)
                : authority.checkNavigationCanary(sid,subject,account,organization,null);
        return access.execute(sid,subject,context->{
            SessionAccountGrant grant=admin?authority.require(context,account,organization,group,false,true,false,false,canaryDecision).grant()
                    : canaryDecision!=null?authority.require(context,account,organization,null,false,false,false,false,canaryDecision).grant()
                            : authorize(context,account,organization,false,false);
            UUID anchor=admin?null:organizations.visibility(account,grant.authMethod(),organization).orElseThrow(GroupJoinService::denied).membershipId();
            List<GroupJoinRequest> rows=requests.list(organization,admin?group:null,admin?null:account,anchor,status,after,limit+1);
            List<GroupJoinResponse> page=rows.stream().limit(limit).map(GroupJoinResponse::from).toList();
            sessions.touch(context.session(),grant,context.now());
            return new Page(page,rows.size()>limit?page.getLast().id():null);
        });
    }
    private SessionAccountGrant authorize(SessionAccess.Context context,UUID account,UUID organization,boolean admin) {
        return authorize(context,account,organization,admin,true);
    }
    private SessionAccountGrant authorize(SessionAccess.Context context,UUID account,UUID organization,boolean admin,boolean mutation) {
        SessionAccountGrant grant=sessions.liveGrant(context.session(),account,context.now()).orElseThrow(GroupJoinService::denied);
        if((admin && !Set.of("LOGIN","PASSWORD").contains(grant.authMethod())) || !groups.lockOrganization(organization,mutation)) throw denied();
        OrganizationRepository.Visibility visible=organizations.visibility(account,grant.authMethod(),organization).orElseThrow(GroupJoinService::denied);
        if(organizations.university(organization)) throw denied();
        if(admin && visible.role()!=OrganizationMembership.Role.OWNER && visible.role()!=OrganizationMembership.Role.ADMIN) throw denied();
        return grant;
    }
    private void requireApproval(UUID organization,UUID group,UUID anchor,Instant now) {
        if(rules.find(organization,group).filter(rule->rule.joining()==com.unidocs.auth.group.domain.GroupRule.Joining.APPROVAL).isEmpty()
                || !rules.discoverable(organization,group,anchor,now))throw denied();
    }
    private void changed(GroupJoinRequest request,SessionAccess.Context context,UUID account,String event) {
        sessions.audit(context.owner().userId(),account,context.session().id(),event,context.now());
        outbox.groupJoinChanged(request,event,context.now());
        metrics.counter("group.join","outcome",request.status().name().toLowerCase(java.util.Locale.ROOT)).increment();
    }
    private static boolean databaseTime(Instant instant) {
        return instant!=null && instant.getNano()%1000==0 && !instant.isBefore(Instant.parse("1000-01-01T00:00:00Z"))
                && instant.isBefore(Instant.parse("+10000-01-01T00:00:00Z"));
    }
    private static String role(String value) { try { return GroupMembership.normalizedRole(value); } catch(IllegalArgumentException invalid) { throw badRequest(); } }
    private static String reason(String value) { try { return GroupJoinRequest.normalizedReason(value); } catch(IllegalArgumentException invalid) { throw badRequest(); } }
    private static GroupFailure denied() { return new GroupFailure(HttpStatus.FORBIDDEN); }
    private static GroupFailure badRequest() { return new GroupFailure(HttpStatus.BAD_REQUEST); }
    private static GroupFailure conflict() { return new GroupFailure(HttpStatus.CONFLICT); }
    private static String hash(String canonical) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8))); }
        catch(NoSuchAlgorithmException unavailable) { throw new IllegalStateException(unavailable); }
    }
}
