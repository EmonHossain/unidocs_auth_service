package com.unidocs.auth.group.application;

import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.authorization.application.ProfessionalAuthorizationService;
import com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary;
import com.unidocs.auth.group.api.GroupAssignmentRequest;
import com.unidocs.auth.group.api.GroupResponse;
import com.unidocs.auth.group.domain.Group;
import com.unidocs.auth.group.domain.GroupMembership;
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
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class GroupMembershipCanaryTests {
    /** A selected navigation dependency failure cannot enumerate memberships or enter a session transaction. */
    @org.junit.jupiter.api.Test
    void ownMembershipListFailsClosedBeforeReadsWhenGraphPreflightIsUnavailable() {
        UUID session=UUID.randomUUID(),subject=UUID.randomUUID(),organization=UUID.randomUUID(),account=UUID.randomUUID();
        GroupMembershipRepository members=mock(GroupMembershipRepository.class);
        SessionAccess access=mock(SessionAccess.class);
        ProfessionalSpiceDbCanary canary=mock(ProfessionalSpiceDbCanary.class);
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider=mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(canary.applies(organization,"workspace.read")).thenReturn(true);
        when(canary.checkContent(session,subject,account,organization,null,"workspace.read",false)).thenThrow(
                new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE,"SPICEDB_AUTHORIZATION_UNAVAILABLE"));
        GroupMembershipService service=new GroupMembershipService(members,mock(GroupRepository.class),mock(OrganizationRepository.class),
                mock(SessionRepository.class),access,mock(OutboxRepository.class),mock(OrganizationSnapshotStore.class),
                mock(Validator.class),new SimpleMeterRegistry(),mock(GroupRuleRepository.class),mock(ProfessionalAuthorizationService.class),provider);

        assertThrows(OperationAuthorizationFailure.class,()->service.mine(session,subject,account,organization,null,10));
        verifyNoInteractions(access,members);
    }

    /** Final projection revocation prevents any membership result or activity update. */
    @org.junit.jupiter.api.Test
    void ownMembershipListCannotReturnRowsAfterFinalGraphRevocation() {
        UUID session=UUID.randomUUID(),subject=UUID.randomUUID(),organization=UUID.randomUUID(),account=UUID.randomUUID();
        Instant now=Instant.parse("2026-11-01T10:00:00Z");
        GroupMembershipRepository members=mock(GroupMembershipRepository.class);
        GroupRepository groups=mock(GroupRepository.class);
        OrganizationRepository organizations=mock(OrganizationRepository.class);
        SessionRepository sessions=mock(SessionRepository.class);
        SessionAccess access=mock(SessionAccess.class);
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        com.unidocs.auth.session.domain.SessionAccountGrant grant=mock(com.unidocs.auth.session.domain.SessionAccountGrant.class);
        ProfessionalAuthorizationService professional=mock(ProfessionalAuthorizationService.class);
        ProfessionalSpiceDbCanary canary=mock(ProfessionalSpiceDbCanary.class);
        ProfessionalSpiceDbCanary.Decision proof=mock(ProfessionalSpiceDbCanary.Decision.class);
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider=mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(canary.applies(organization,"workspace.read")).thenReturn(true);
        when(canary.checkContent(session,subject,account,organization,null,"workspace.read",false)).thenReturn(proof);
        when(access.execute(eq(session),eq(subject),any())).thenAnswer(call->
                call.<java.util.function.Function<SessionAccess.Context,Object>>getArgument(2).apply(context));
        when(context.now()).thenReturn(now);
        when(sessions.liveGrant(null,account,now)).thenReturn(Optional.of(grant));
        when(grant.authMethod()).thenReturn("LOGIN");
        when(groups.lockOrganization(organization,false)).thenReturn(true);
        when(organizations.visibility(account,"LOGIN",organization)).thenReturn(Optional.of(
                new OrganizationRepository.Visibility(UUID.randomUUID(),com.unidocs.auth.organization.domain.OrganizationMembership.Role.OWNER,1,1)));
        when(professional.professional(organization)).thenReturn(true);
        when(canary.revalidate(proof,context,account,organization)).thenThrow(
                new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE,"SPICEDB_AUTHORIZATION_UNAVAILABLE"));
        GroupMembershipService service=new GroupMembershipService(members,groups,organizations,sessions,access,
                mock(OutboxRepository.class),mock(OrganizationSnapshotStore.class),mock(Validator.class),
                new SimpleMeterRegistry(),mock(GroupRuleRepository.class),professional,provider);

        assertThrows(OperationAuthorizationFailure.class,()->service.mine(session,subject,account,organization,null,10));
        verify(canary).requireContentDecision(organization,null,"workspace.read",false,proof);
        verifyNoInteractions(members);
        verify(sessions,never()).touch(any(),any(),any());
    }

    @org.junit.jupiter.api.Test
    void staleGraphDecisionInFinalTransactionCannotAssignOrAudit() {
        UUID session=UUID.randomUUID(),subject=UUID.randomUUID(),organization=UUID.randomUUID();
        UUID group=UUID.randomUUID(),actor=UUID.randomUUID(),member=UUID.randomUUID();
        Instant now=Instant.parse("2026-10-19T12:00:00Z");
        GroupAssignmentRequest request=new GroupAssignmentRequest(actor,UUID.randomUUID(),member,"member",
                now.minusSeconds(60),null);
        GroupMembershipRepository members=mock(GroupMembershipRepository.class);
        GroupRepository groups=mock(GroupRepository.class);
        GroupResponse response=mock(GroupResponse.class);
        Validator validator=mock(Validator.class);
        SessionAccess access=mock(SessionAccess.class);
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        SessionRepository sessions=mock(SessionRepository.class);
        OutboxRepository outbox=mock(OutboxRepository.class);
        ProfessionalAuthorizationService professional=mock(ProfessionalAuthorizationService.class);
        ProfessionalSpiceDbCanary canary=mock(ProfessionalSpiceDbCanary.class);
        ProfessionalSpiceDbCanary.Decision decision=mock(ProfessionalSpiceDbCanary.Decision.class);
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider=mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(validator.validate(request)).thenReturn(Set.of());
        UUID targetGroup=UUID.randomUUID();
        when(members.accountGroup(member)).thenReturn(Optional.of(targetGroup));
        when(groups.find(organization,group)).thenReturn(Optional.of(new GroupRepository.Visible(response,1)));
        when(response.type()).thenReturn(Group.Type.TEAM);
        when(canary.applies(organization,"organization.department.assign")).thenReturn(true);
        when(canary.applies(organization,"organization.group.assign")).thenReturn(true);
        when(canary.checkAssignment(session,subject,actor,organization,group,member,"organization.group.assign"))
                .thenReturn(decision);
        when(decision.enforcing()).thenReturn(true);
        when(decision.operation()).thenReturn("organization.group.assign");
        when(decision.group()).thenReturn(group);
        when(professional.professional(organization)).thenReturn(true);
        when(context.now()).thenReturn(now);
        when(sessions.liveGrant(null,actor,now)).thenReturn(Optional.of(mock(com.unidocs.auth.session.domain.SessionAccountGrant.class)));
        when(access.executeForGroups(eq(session),eq(subject),eq(List.of(targetGroup)),any())).thenAnswer(call ->
                call.<java.util.function.Function<SessionAccess.Context,Object>>getArgument(3).apply(context));
        doThrow(new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE,"SPICEDB_AUTHORIZATION_UNAVAILABLE"))
                .when(canary).revalidate(decision,context,actor,organization);
        GroupMembershipService service=new GroupMembershipService(members,groups,mock(OrganizationRepository.class),
                sessions,access,outbox,mock(OrganizationSnapshotStore.class),validator,new SimpleMeterRegistry(),
                mock(GroupRuleRepository.class),professional,provider);

        assertThrows(OperationAuthorizationFailure.class,
                ()->service.assign(session,subject,organization,group,request));
        verify(canary).requireAssignmentRecipient(decision,member);
        verify(members,never()).create(any(),any(),any(),any());
        verifyNoInteractions(outbox);
        verify(sessions,never()).audit(any(),any(),any(),anyString(),any());
    }

    /**
     * Keeps legacy recipient matching outside enforcement and forbids a second SQL authority engine inside it.
     * @param enforcing whether the cohort uses graph-authoritative matching
     */
    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans={false,true})
    void unassignSelectsOnlyItsConfiguredAuthorityEngine(boolean enforcing) {
        UUID session=UUID.randomUUID(),subject=UUID.randomUUID(),organization=UUID.randomUUID();
        UUID group=UUID.randomUUID(),actor=UUID.randomUUID(),target=UUID.randomUUID(),membership=UUID.randomUUID();
        UUID targetGroup=UUID.randomUUID();
        Instant now=Instant.parse("2026-10-19T12:00:00Z");
        GroupMembershipRepository members=mock(GroupMembershipRepository.class);
        GroupRepository groups=mock(GroupRepository.class);
        GroupResponse response=mock(GroupResponse.class);
        SessionAccess access=mock(SessionAccess.class);
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        SessionRepository sessions=mock(SessionRepository.class);
        com.unidocs.auth.session.domain.SessionAccountGrant grant=mock(com.unidocs.auth.session.domain.SessionAccountGrant.class);
        ProfessionalAuthorizationService professional=mock(ProfessionalAuthorizationService.class);
        ProfessionalSpiceDbCanary canary=mock(ProfessionalSpiceDbCanary.class);
        ProfessionalSpiceDbCanary.Decision decision=mock(ProfessionalSpiceDbCanary.Decision.class);
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider=mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(members.memberAccount(organization,group,membership)).thenReturn(Optional.of(target));
        when(members.accountGroup(target)).thenReturn(Optional.of(targetGroup));
        when(groups.find(organization,group)).thenReturn(Optional.of(new GroupRepository.Visible(response,1)));
        when(response.type()).thenReturn(Group.Type.TEAM);
        when(canary.applies(organization,"organization.group.unassign")).thenReturn(true);
        when(canary.checkAssignment(session,subject,actor,organization,group,target,"organization.group.unassign"))
                .thenReturn(decision);
        when(decision.enforcing()).thenReturn(enforcing);
        when(decision.operation()).thenReturn("organization.group.unassign");
        when(decision.group()).thenReturn(group);
        when(professional.professional(organization)).thenReturn(true);
        when(context.now()).thenReturn(now);
        when(sessions.liveGrant(null,actor,now)).thenReturn(Optional.of(grant));
        GroupMembership revoked=new GroupMembership(membership,organization,group,target,UUID.randomUUID(),"member",
                GroupMembership.MembershipType.PERMANENT,GroupMembership.Source.ORGANIZATION_ASSIGNMENT,null,
                GroupMembership.Status.REVOKED,now.minusSeconds(100),null,2,now.minusSeconds(100),now);
        when(members.find(organization,group,membership)).thenReturn(Optional.of(revoked));
        when(access.executeForGroups(eq(session),eq(subject),eq(List.of(targetGroup)),any())).thenAnswer(call ->
                call.<java.util.function.Function<SessionAccess.Context,Object>>getArgument(3).apply(context));
        GroupMembershipService service=new GroupMembershipService(members,groups,mock(OrganizationRepository.class),
                sessions,access,mock(OutboxRepository.class),mock(OrganizationSnapshotStore.class),mock(Validator.class),
                new SimpleMeterRegistry(),mock(GroupRuleRepository.class),professional,provider);

        assertEquals(GroupMembership.Status.REVOKED,
                service.revoke(session,subject,organization,group,membership,actor).status());
        if(enforcing)verify(professional,never()).assignmentRecipient(any(),any(),any(),any(),any(),anyString());
        else verify(professional).assignmentRecipient(context,actor,organization,group,target,"organization.group.unassign");
        verify(canary).requireAssignmentRecipient(decision,target);
        if(enforcing)verify(professional,never()).require(any(),any(),any(),any(),anyString(),anyString());
        else verify(professional).require(context,actor,organization,group,"auth-service","organization.group.unassign");
    }

    @ParameterizedTest
    @EnumSource(value=Group.Type.class,names={"TEAM","DEPARTMENT"})
    void deniedGraphPreflightCannotAssignMembership(Group.Type type) {
        UUID session=UUID.randomUUID(),subject=UUID.randomUUID(),organization=UUID.randomUUID();
        UUID group=UUID.randomUUID(),actor=UUID.randomUUID(),member=UUID.randomUUID();
        GroupAssignmentRequest request=new GroupAssignmentRequest(actor,UUID.randomUUID(),member,"member",
                Instant.parse("2026-10-18T12:00:00Z"),null);
        GroupMembershipRepository memberships=mock(GroupMembershipRepository.class);
        GroupRepository groups=mock(GroupRepository.class);
        GroupResponse response=mock(GroupResponse.class);
        Validator validator=mock(Validator.class);
        SessionAccess access=mock(SessionAccess.class);
        OutboxRepository outbox=mock(OutboxRepository.class);
        ProfessionalSpiceDbCanary canary=mock(ProfessionalSpiceDbCanary.class);
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider=mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(validator.validate(request)).thenReturn(Set.of());
        when(memberships.accountGroup(member)).thenReturn(Optional.of(UUID.randomUUID()));
        when(groups.find(organization,group)).thenReturn(Optional.of(new GroupRepository.Visible(response,1)));
        when(response.type()).thenReturn(type);
        when(canary.applies(organization,"organization.department.assign")).thenReturn(true);
        when(canary.applies(organization,"organization.group.assign")).thenReturn(true);
        String selected=type==Group.Type.DEPARTMENT?"organization.department.assign":"organization.group.assign";
        when(canary.checkAssignment(session,subject,actor,organization,group,member,selected))
                .thenThrow(new OperationAuthorizationFailure(HttpStatus.FORBIDDEN,"PROFESSIONAL_AUTHORITY_DENIED"));
        GroupMembershipService service=new GroupMembershipService(memberships,groups,mock(OrganizationRepository.class),
                mock(SessionRepository.class),access,outbox,mock(OrganizationSnapshotStore.class),validator,
                new SimpleMeterRegistry(),mock(GroupRuleRepository.class),mock(ProfessionalAuthorizationService.class),provider);
        assertThrows(OperationAuthorizationFailure.class,()->service.assign(session,subject,organization,group,request));
        verifyNoInteractions(access,outbox);
        verify(memberships,never()).create(any(),any(),any(),any());
    }
}
