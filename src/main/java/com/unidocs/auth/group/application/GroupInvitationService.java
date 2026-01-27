package com.unidocs.auth.group.application;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.unidocs.auth.group.api.*;
import com.unidocs.auth.group.domain.*;
import com.unidocs.auth.group.persistence.*;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import static com.unidocs.auth.group.application.GroupRuleService.*;

@Service
@Transactional(propagation=Propagation.NEVER)
public class GroupInvitationService {
    public record View(UUID id,UUID groupId,UUID memberAccountId,String role,Instant validFrom,Instant validUntil,
            Instant expiresAt,String status,long version,UUID membershipId) { }
    public record Page(List<View> invitations,UUID nextCursor) { }
    private record Result(View response,long version) { }
    private final GroupInvitationRepository invitations;
    private final GroupMembershipRepository members;
    private final GroupRuleRepository rules;
    private final OrganizationRepository organizations;
    private final GroupAuthority authority;
    private final GroupRuleService changes;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final OutboxRepository outbox;
    public GroupInvitationService(GroupInvitationRepository invitations,GroupMembershipRepository members,GroupRuleRepository rules,
            OrganizationRepository organizations,GroupAuthority authority,GroupRuleService changes,SessionAccess access,SessionRepository sessions,OutboxRepository outbox) {
        this.invitations=invitations;this.members=members;this.rules=rules;this.organizations=organizations;this.authority=authority;this.changes=changes;
        this.access=access;this.sessions=sessions;this.outbox=outbox;
    }
    public View issue(UUID sid,UUID subject,UUID organization,UUID group,GroupInvitationRequests.Issue command) {
        changes.validate(command);
        String role;
        try { role=GroupMembership.normalizedRole(command.role()); }catch(IllegalArgumentException invalid){throw badRequest();}
        if(!databaseTime(command.validFrom())||!databaseTime(command.expiresAt())||(command.validUntil()!=null&&
                (!databaseTime(command.validUntil())||!command.validUntil().isAfter(command.validFrom()))))throw badRequest();
        String fingerprint=hash(group+"\n"+command.memberAccountId()+"\n"+role+"\n"+command.validFrom()+"\n"+command.validUntil()+"\n"+command.expiresAt());
        UUID targetGroup=members.accountGroup(command.memberAccountId()).orElseThrow(GroupAuthority::denied);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision=
                authority.checkManagerCanary(sid,subject,command.accountId(),organization,group);
        try {
            return access.executeForGroups(sid,subject,List.of(targetGroup),context->{
                GroupAuthority.Access actor=authority.require(context,command.accountId(),organization,group,true,true,false,true,canaryDecision);
                // Professional collaboration uses exact Document invitations; it never assigns team membership.
                if(!rules.university(organization)) throw GroupAuthority.denied();
                if(rules.find(organization,group).orElseThrow(GroupAuthority::denied).joining()!=GroupRule.Joining.INVITATION_ONLY)throw GroupAuthority.denied();
                OrganizationRepository.Visibility target=organizations.visibility(command.memberAccountId(),"PASSWORD",organization).orElseThrow(GroupAuthority::denied);
                if(!rules.courseEligible(organization,group,target.membershipId(),context.now()))throw GroupAuthority.denied();
                GroupInvitationRepository.Invitation retry=invitations.retry(organization,command.accountId(),command.requestId()).orElse(null);
                if(retry!=null) {
                    if(!fingerprint.equals(retry.fingerprint())||!retry.anchor().equals(target.membershipId()))throw conflict();return view(retry);
                }
                if(!command.expiresAt().isAfter(context.now())||command.expiresAt().isAfter(context.now().plus(Duration.ofDays(30)))||
                        (command.validUntil()!=null&&!command.validUntil().isAfter(context.now())))throw badRequest();
                GroupInvitationRepository.Invitation invitation=new GroupInvitationRepository.Invitation(UUID.randomUUID(),organization,group,command.memberAccountId(),
                        target.membershipId(),command.accountId(),command.requestId(),fingerprint,role,command.validFrom(),command.validUntil(),command.expiresAt(),"PENDING",1,null);
                invitations.create(invitation,context.now());
                changed(context,command.accountId(),invitation,"GROUP_INVITATION_CREATED");
                sessions.touch(context.session(),actor.grant(),context.now());return view(invitation);
            });
        }catch(DataIntegrityViolationException duplicate){throw conflict();}
    }
    public View act(UUID sid,UUID subject,UUID organization,UUID group,UUID id,GroupInvitationRequests.Action command,boolean accept) {
        changes.validate(command);
        GroupInvitationRepository.Invitation original=invitations.find(organization,id).orElseThrow(GroupAuthority::denied);
        UUID targetGroup=members.accountGroup(original.accountId()).orElseThrow(GroupAuthority::denied);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision=accept
                ? authority.checkNavigationCanary(sid,subject,command.accountId(),organization,group):
                authority.checkManagerCanary(sid,subject,command.accountId(),organization,group);
        Result result=access.executeForGroups(sid,subject,List.of(targetGroup),context->{
            GroupAuthority.Access actor=authority.require(context,command.accountId(),organization,group,true,!accept,false,true,canaryDecision);
            if(accept && !rules.university(organization)) throw GroupAuthority.denied();
            GroupInvitationRepository.Invitation invitation=invitations.find(organization,id).orElseThrow(GroupAuthority::denied);
            if(!invitation.groupId().equals(group))throw GroupAuthority.denied();
            if(accept && (!invitation.accountId().equals(command.accountId())||!invitation.anchor().equals(actor.visibility().membershipId())))throw GroupAuthority.denied();
            if(invitation.status().equals(accept?"ACCEPTED":"REVOKED") && invitation.version()==command.expectedVersion()+1)return new Result(view(invitation),0);
            if(!invitation.status().equals("PENDING")||invitation.version()!=command.expectedVersion())throw conflict();
            UUID membershipId=null;long version=0;
            if(accept) {
                GroupRule rule=rules.find(organization,group).orElseThrow(GroupAuthority::denied);
                if(!rules.courseEligible(organization,group,invitation.anchor(),context.now()) || rule.joining()!=GroupRule.Joining.INVITATION_ONLY || !invitation.expiresAt().isAfter(context.now()) ||
                        (invitation.validUntil()!=null&&!invitation.validUntil().isAfter(context.now())))throw GroupAuthority.denied();
                if(rule.discovery()==GroupRule.Discovery.DEPARTMENT && !rules.effective(organization,rule.departmentGroupId(),invitation.anchor(),context.now(),false))throw GroupAuthority.denied();
                if(members.hasActiveAssignment(group,invitation.anchor()))throw conflict();
                GroupMembership member=new GroupMembership(UUID.randomUUID(),organization,group,command.accountId(),invitation.anchor(),invitation.role(),
                        invitation.validUntil()==null?GroupMembership.MembershipType.PERMANENT:GroupMembership.MembershipType.TEMPORARY,
                        GroupMembership.Source.INVITATION,id.toString(),GroupMembership.Status.ACTIVE,invitation.validFrom(),invitation.validUntil(),1,context.now(),context.now());
                members.create(member,command.accountId(),id,invitation.fingerprint());membershipId=member.id();
                version=members.advanceOrganization(organization,context.now());
                sessions.audit(context.owner().userId(),command.accountId(),sid,"GROUP_MEMBER_ASSIGNED",context.now());
                outbox.groupMembershipChanged(member,version,"GROUP_MEMBER_ASSIGNED",context.now());
            }
            invitations.finish(id,membershipId,context.now());
            GroupInvitationRepository.Invitation updated=invitations.find(organization,id).orElseThrow();
            changed(context,command.accountId(),updated,accept?"GROUP_INVITATION_ACCEPTED":"GROUP_INVITATION_REVOKED");
            sessions.touch(context.session(),actor.grant(),context.now());return new Result(view(updated),version);
        });
        changes.invalidate(organization,result.version());return result.response();
    }
    public Page mine(UUID sid,UUID subject,UUID organization,UUID account,UUID after,int limit) {
        if(limit<1||limit>100)throw badRequest();
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=
                authority.checkNavigationCanary(sid,subject,account,organization,null);
        return access.execute(sid,subject,context->{
            GroupAuthority.Access actor=authority.require(context,account,organization,null,false,false,false,true,decision);
            List<GroupInvitationRepository.Invitation> rows=invitations.pending(organization,actor.visibility().membershipId(),after,limit+1,context.now());
            return new Page(rows.stream().limit(limit).map(GroupInvitationService::view).toList(),rows.size()>limit?rows.get(limit-1).id():null);
        });
    }
    private void changed(SessionAccess.Context context,UUID account,GroupInvitationRepository.Invitation invitation,String event) {
        sessions.audit(context.owner().userId(),account,context.session().id(),event,context.now());
        outbox.lifecycle("GROUP_INVITATION",invitation.id(),invitation.version(),event,account,invitation.organizationId(),null,context.now());
    }
    private static View view(GroupInvitationRepository.Invitation i) {
        return new View(i.id(),i.groupId(),i.accountId(),i.role(),i.validFrom(),i.validUntil(),i.expiresAt(),i.status(),i.version(),i.membershipId());
    }
    private static boolean databaseTime(Instant instant) {
        return instant!=null&&instant.getNano()%1000==0&&!instant.isBefore(Instant.parse("1000-01-01T00:00:00Z"))&&instant.isBefore(Instant.parse("+10000-01-01T00:00:00Z"));
    }
}
