package com.unidocs.auth.group.application;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import jakarta.validation.Validator;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import com.unidocs.auth.group.api.*;
import com.unidocs.auth.group.domain.*;
import com.unidocs.auth.group.persistence.*;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;

@Service
@Transactional(propagation=Propagation.NEVER)
public class GroupRuleService {
    public record Discovered(GroupResponse group,GroupRule rule,boolean member) { }
    public record Page(List<Discovered> groups,UUID nextCursor) { }
    private record Mutation<T>(T response,long version) { }
    private final GroupRuleRepository rules;
    private final GroupRepository groups;
    private final GroupMembershipRepository members;
    private final AcademicRepository academics;
    private final GroupAuthority authority;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final OutboxRepository outbox;
    private final OrganizationSnapshotStore snapshots;
    private final Validator validator;
    private final io.micrometer.core.instrument.MeterRegistry metrics;
    private final com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary;
    @Autowired
    public GroupRuleService(GroupRuleRepository rules,GroupRepository groups,GroupMembershipRepository members,AcademicRepository academics,
            GroupAuthority authority,SessionAccess access,SessionRepository sessions,OutboxRepository outbox,OrganizationSnapshotStore snapshots,Validator validator,
            io.micrometer.core.instrument.MeterRegistry metrics,
            ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> canaryProvider) {
        this(rules,groups,members,academics,authority,access,sessions,outbox,snapshots,validator,metrics,canaryProvider.getIfAvailable());
    }
    public GroupRuleService(GroupRuleRepository rules,GroupRepository groups,GroupMembershipRepository members,AcademicRepository academics,
            GroupAuthority authority,SessionAccess access,SessionRepository sessions,OutboxRepository outbox,OrganizationSnapshotStore snapshots,Validator validator,io.micrometer.core.instrument.MeterRegistry metrics) {
        this(rules,groups,members,academics,authority,access,sessions,outbox,snapshots,validator,metrics,
                (com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary)null);
    }
    private GroupRuleService(GroupRuleRepository rules,GroupRepository groups,GroupMembershipRepository members,AcademicRepository academics,
            GroupAuthority authority,SessionAccess access,SessionRepository sessions,OutboxRepository outbox,OrganizationSnapshotStore snapshots,Validator validator,
            io.micrometer.core.instrument.MeterRegistry metrics,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary) {
        this.rules=rules;this.groups=groups;this.members=members;this.academics=academics;this.authority=authority;this.access=access;
        this.sessions=sessions;this.outbox=outbox;this.snapshots=snapshots;this.validator=validator;this.metrics=metrics;
        this.canary=canary;
    }
    public GroupRule configure(UUID sid,UUID subject,UUID organization,UUID group,GroupRuleRequests.Configure command) {
        validate(command);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=
                checkCanary(sid,subject,organization,command.accountId());
        Mutation<GroupRule> result=access.execute(sid,subject,context->{
            GroupAuthority.Access actor=authority.requireCatalog(context,command.accountId(),organization,group,true,decision);
            if(!rules.university(organization) && command.joining()!=GroupRule.Joining.INVITATION_ONLY) throw badRequest();
            GroupRule old=rules.find(organization,group).orElseThrow(GroupAuthority::denied);
            if(groups.find(organization,group).orElseThrow().group().type()==Group.Type.DEPARTMENT && command.joining()==GroupRule.Joining.OPEN)throw badRequest();
            boolean course=rules.university(organization) && groups.find(organization,group).orElseThrow().group().type()==Group.Type.COURSE;
            if(course!=(command.joining()==GroupRule.Joining.COURSE_ENROLLMENT)) throw badRequest();
            if(course) {
                // Course offering identity is immutable after binding: changing it could expose previous semester content.
                AcademicRepository.Semester semester=academics.semester(organization,command.semesterId()).orElseThrow(GroupRuleService::badRequest);
                if(!semester.endsAt().isAfter(context.now()) || (old.semesterId()!=null && !old.semesterId().equals(command.semesterId()))) throw conflict();
            } else if(command.semesterId()!=null) throw badRequest();
            if(command.discovery()==GroupRule.Discovery.DEPARTMENT) {
                if(command.departmentGroupId()==null || command.departmentGroupId().equals(group) || groups.find(organization,command.departmentGroupId())
                        .filter(row->row.group().type()==Group.Type.DEPARTMENT).isEmpty()) throw badRequest();
            } else if(command.departmentGroupId()!=null) throw badRequest();
            boolean same=old.discovery()==command.discovery() && old.joining()==command.joining()
                    && Objects.equals(old.departmentGroupId(),command.departmentGroupId()) && Objects.equals(old.semesterId(),command.semesterId());
            if(old.version()!=command.expectedVersion()) {
                if(same && old.version()==command.expectedVersion()+1) return new Mutation<>(old,0);
                throw conflict();
            }
            if(same)return new Mutation<>(old,0);
            rules.update(organization,new GroupRule(group,command.discovery(),command.joining(),command.departmentGroupId(),command.semesterId(),old.version()));
            long version=changed(context,command.accountId(),organization,group,old.version()+1,"GROUP_RULE_CHANGED");
            sessions.touch(context.session(),actor.grant(),context.now());
            return new Mutation<>(rules.find(organization,group).orElseThrow(),version);
        });
        invalidate(organization,result.version());return result.response();
    }
    public Page discover(UUID sid,UUID subject,UUID organization,UUID account,UUID after,int limit) {
        if(limit<1||limit>100)throw badRequest();
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=
                authority.checkNavigationCanary(sid,subject,account,organization,null);
        return access.execute(sid,subject,context->{
            GroupAuthority.Access actor=authority.require(context,account,organization,null,false,false,false,true,decision);
            List<UUID> ids=rules.discoverableIds(organization,actor.visibility().membershipId(),after,limit+1,context.now());
            List<UUID> pageIds=ids.stream().limit(limit).toList();
            java.util.Map<UUID,GroupResponse> metadata=groups.findAll(organization,pageIds).stream().collect(java.util.stream.Collectors.toMap(GroupResponse::id,row->row));
            java.util.Map<UUID,GroupRule> policies=rules.findAll(organization,pageIds).stream().collect(java.util.stream.Collectors.toMap(GroupRule::groupId,row->row));
            java.util.Set<UUID> effective=java.util.Set.copyOf(rules.effectiveGroups(organization,actor.visibility().membershipId(),pageIds,context.now()));
            List<Discovered> rows=pageIds.stream().map(id->new Discovered(metadata.get(id),policies.get(id),effective.contains(id))).toList();
            sessions.touch(context.session(),actor.grant(),context.now());
            return new Page(rows,ids.size()>limit?rows.getLast().group().id():null);
        });
    }
    public GroupRule managedRule(UUID sid,UUID subject,UUID organization,UUID account,UUID group) {
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=
                checkCanary(sid,subject,organization,account);
        return access.execute(sid,subject,context->{
            authority.requireCatalog(context,account,organization,group,false,decision);
            return rules.find(organization,group).orElseThrow(GroupAuthority::denied);
        });
    }
    private com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision checkCanary(
            UUID sid,UUID subject,UUID organization,UUID account) {
        return canary!=null && canary.applies(organization,"organization.group.create")
                ? canary.check(sid,subject,account,organization):null;
    }
    public Discovered detail(UUID sid,UUID subject,UUID organization,UUID account,UUID group) {
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=
                authority.checkNavigationCanary(sid,subject,account,organization,group);
        return access.execute(sid,subject,context->{
            GroupAuthority.Access actor=authority.require(context,account,organization,group,false,false,false,true,decision);
            if(!rules.discoverable(organization,group,actor.visibility().membershipId(),context.now()))throw GroupAuthority.denied();
            return new Discovered(groups.find(organization,group).orElseThrow().group(),rules.find(organization,group).orElseThrow(),
                    rules.effective(organization,group,actor.visibility().membershipId(),context.now(),false));
        });
    }
    public GroupMembershipResponse join(UUID sid,UUID subject,UUID organization,UUID group,GroupRuleRequests.Join command) {
        validate(command);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=
                authority.checkNavigationCanary(sid,subject,command.accountId(),organization,group);
        Mutation<GroupMembershipResponse> result=access.execute(sid,subject,context->{
            GroupAuthority.Access actor=authority.require(context,command.accountId(),organization,group,true,false,false,true,decision);
            if(!rules.university(organization)) throw GroupAuthority.denied();
            GroupRule rule=rules.find(organization,group).orElseThrow(GroupAuthority::denied);
            if(rule.joining()!=GroupRule.Joining.OPEN || !rules.discoverable(organization,group,actor.visibility().membershipId(),context.now()))throw GroupAuthority.denied();
            String fingerprint=hash("OPEN\n"+group);
            GroupMembershipRepository.Assignment retry=members.assignment(organization,command.accountId(),command.requestId()).orElse(null);
            if(retry!=null) {
                if(!retry.fingerprint().equals(fingerprint)||!retry.membership().organizationMembershipId().equals(actor.visibility().membershipId()))throw conflict();
                return new Mutation<>(GroupMembershipResponse.from(retry.membership(),context.now(),true),0);
            }
            if(members.hasActiveAssignment(group,actor.visibility().membershipId()))throw conflict();
            GroupMembership member=new GroupMembership(UUID.randomUUID(),organization,group,command.accountId(),actor.visibility().membershipId(),"member",
                    GroupMembership.MembershipType.PERMANENT,GroupMembership.Source.OPEN_JOIN,null,GroupMembership.Status.ACTIVE,context.now(),null,1,context.now(),context.now());
            members.create(member,command.accountId(),command.requestId(),fingerprint);
            long version=members.advanceOrganization(organization,context.now());
            sessions.audit(context.owner().userId(),command.accountId(),sid,"GROUP_MEMBER_ASSIGNED",context.now());
            outbox.groupMembershipChanged(member,version,"GROUP_MEMBER_ASSIGNED",context.now());
            sessions.touch(context.session(),actor.grant(),context.now());
            return new Mutation<>(GroupMembershipResponse.from(member,context.now(),true),version);
        });
        invalidate(organization,result.version());return result.response();
    }
    public long changed(SessionAccess.Context context,UUID account,UUID organization,UUID aggregate,long aggregateVersion,String event) {
        long version=members.advanceOrganization(organization,context.now());
        sessions.audit(context.owner().userId(),account,context.session().id(),event,context.now());
        outbox.lifecycle("GROUP_RULE",aggregate,aggregateVersion,event,account,organization,null,context.now());
        outbox.lifecycle("ORGANIZATION",organization,version,"ORGANIZATION_GROUP_MEMBERSHIP_CHANGED",account,organization,null,context.now());
        metrics.counter("group.rules","outcome",event.toLowerCase(java.util.Locale.ROOT)).increment();
        return version;
    }
    public void invalidate(UUID organization,long version) {
        if(version>0) { try { snapshots.invalidate(organization,version); } catch(RuntimeException unavailable) { metrics.counter("group.rules","outcome","cache_invalidation_failed").increment(); } }
    }
    public void validate(Object command) { if(command==null||!validator.validate(command).isEmpty())throw badRequest(); }
    public static GroupFailure badRequest() { return new GroupFailure(HttpStatus.BAD_REQUEST); }
    public static GroupFailure conflict() { return new GroupFailure(HttpStatus.CONFLICT); }
    public static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch(NoSuchAlgorithmException unavailable) { throw new IllegalStateException(unavailable); }
    }
}
