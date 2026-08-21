package com.unidocs.auth.group.application;

import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import com.unidocs.auth.group.api.GroupInvitationRequests;
import com.unidocs.auth.group.api.GroupJoinRequests;
import com.unidocs.auth.group.domain.GroupJoinRequest;
import com.unidocs.auth.group.persistence.GroupInvitationRepository;
import com.unidocs.auth.group.persistence.GroupJoinRepository;
import com.unidocs.auth.group.persistence.GroupMembershipRepository;
import com.unidocs.auth.group.persistence.GroupRepository;
import com.unidocs.auth.group.persistence.GroupRuleRepository;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.validation.Validator;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Professional collaboration may not use institutional enrollment as an alternate membership allow path. */
class ProfessionalEnrollmentBoundaryTests {
    /**
     * Calls enrollment services directly after successful authority admission and requires no membership/audit/outbox write.
     * @param entry direct application-service entry
     */
    @ParameterizedTest @ValueSource(strings={"ISSUE","ACCEPT","APPROVE"})
    void professionalEnrollmentCannotManufactureMembershipAfterAuthorityAllow(String entry) {
        UUID session=UUID.randomUUID(),account=UUID.randomUUID(),organization=UUID.randomUUID(),group=UUID.randomUUID();
        UUID target=UUID.randomUUID(),targetGroup=UUID.randomUUID(),id=UUID.randomUUID();
        Instant now=Instant.parse("2026-10-31T12:00:00Z");
        SessionAccess access=mock(SessionAccess.class);
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        when(context.now()).thenReturn(now);
        doAnswer(call->{
            Function<SessionAccess.Context,Object> command=call.getArgument(3);
            return command.apply(context);
        }).when(access).executeForGroups(eq(session),eq(account),eq(List.of(targetGroup)),any());
        GroupAuthority authority=mock(GroupAuthority.class);
        when(authority.require(eq(context),eq(account),eq(organization),eq(group),eq(true),anyBoolean(),eq(false),eq(true),any()))
                .thenReturn(new GroupAuthority.Access(null,null));
        GroupMembershipRepository members=mock(GroupMembershipRepository.class);
        when(members.accountGroup(target)).thenReturn(Optional.of(targetGroup));
        GroupRuleRepository rules=mock(GroupRuleRepository.class);
        when(rules.university(organization)).thenReturn(false);
        OrganizationRepository organizations=mock(OrganizationRepository.class);
        SessionRepository sessions=mock(SessionRepository.class);
        OutboxRepository outbox=mock(OutboxRepository.class);
        GroupInvitationRepository invitations=mock(GroupInvitationRepository.class);
        GroupJoinRepository requests=mock(GroupJoinRepository.class);
        GroupRuleService changes=mock(GroupRuleService.class);
        GroupInvitationService invitationService=new GroupInvitationService(invitations,members,rules,organizations,
                authority,changes,access,sessions,outbox);
        GroupFailure denied;
        if(entry.equals("ISSUE")) {
            denied=assertThrows(GroupFailure.class,()->invitationService.issue(session,account,organization,group,
                    new GroupInvitationRequests.Issue(account,id,target,"MEMBER",now,null,now.plusSeconds(60))));
        } else if(entry.equals("ACCEPT")) {
            GroupInvitationRepository.Invitation invitation=mock(GroupInvitationRepository.Invitation.class);
            when(invitation.accountId()).thenReturn(target);
            when(invitations.find(organization,id)).thenReturn(Optional.of(invitation));
            denied=assertThrows(GroupFailure.class,()->invitationService.act(session,account,organization,group,id,
                    new GroupInvitationRequests.Action(account,1),true));
        } else {
            GroupJoinRequest request=mock(GroupJoinRequest.class);
            when(request.accountId()).thenReturn(target);
            when(requests.find(organization,group,id)).thenReturn(Optional.of(new GroupJoinRepository.Stored(request,"","")));
            Validator validator=mock(Validator.class);
            when(validator.validate(any())).thenReturn(Set.of());
            GroupJoinService joins=new GroupJoinService(requests,members,mock(GroupRepository.class),organizations,
                    sessions,access,outbox,mock(OrganizationSnapshotStore.class),validator,new SimpleMeterRegistry(),rules,authority);
            denied=assertThrows(GroupFailure.class,()->joins.review(session,account,organization,group,id,
                    new GroupJoinRequests.Review(account,true,"MEMBER",now,null,"Phase 5 direct boundary acceptance")));
        }
        assertEquals(org.springframework.http.HttpStatus.FORBIDDEN,denied.status());
        verify(authority).require(eq(context),eq(account),eq(organization),eq(group),eq(true),anyBoolean(),eq(false),eq(true),any());
        verify(members,never()).create(any(),any(),any(),anyString());
        verifyNoInteractions(sessions,outbox);
        if(entry.equals("ISSUE"))verifyNoInteractions(invitations);
        else if(entry.equals("ACCEPT")) { verify(invitations).find(organization,id);verifyNoMoreInteractions(invitations); }
        else { verify(requests).find(organization,group,id);verifyNoMoreInteractions(requests); }
    }
}
