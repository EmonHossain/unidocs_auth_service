package com.unidocs.auth.group.application;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import jakarta.validation.Validator;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.ObjectProvider;
import com.unidocs.auth.group.api.GroupRequest;
import com.unidocs.auth.group.api.GroupResponse;
import com.unidocs.auth.group.domain.Group;
import com.unidocs.auth.group.persistence.GroupRepository;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.domain.UserSession;
import com.unidocs.auth.session.persistence.SessionRepository;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class GroupServiceTests {
    @Mock GroupRepository groups;
    @Mock OrganizationRepository organizations;
    @Mock SessionAccess access;
    @Mock SessionRepository sessions;
    @Mock OutboxRepository outbox;
    @Mock Validator validator;
    private GroupService service;
    private final UUID account = UUID.randomUUID();
    private final UUID organization = UUID.randomUUID();
    private final UUID sid = UUID.randomUUID();
    private final Instant now = Instant.parse("2026-10-02T12:00:00Z");
    private final GroupRequest request = new GroupRequest(account, UUID.randomUUID(), "Department", Group.Type.DEPARTMENT, null);
    private final UserSession session = new UserSession(sid, UUID.randomUUID(), account, "ACTIVE", now, now, now.plusSeconds(43200), null);

    @BeforeEach void setUp() {
        service = new GroupService(groups, organizations, access, sessions, outbox, validator, new SimpleMeterRegistry(),mock(com.unidocs.auth.authorization.application.ProfessionalAuthorizationService.class));
    }
    @SuppressWarnings("unchecked")
    private void caller(GroupRequest input) {
        when(validator.validate(input)).thenReturn(Set.of());
        SessionAccess.Context context = new SessionAccess.Context(session,
                new SessionRepository.Owner(UUID.randomUUID(), "Caller", account), null, now);
        when(access.execute(eq(sid), eq(account), any())).thenAnswer(invocation ->
                ((Function<SessionAccess.Context, Object>) invocation.getArgument(2)).apply(context));
    }
    private void grant(String method) {
        when(sessions.liveGrant(session, account, now)).thenReturn(Optional.of(new SessionAccountGrant(sid, account,
                "ACTIVE", method, 1, now.plusSeconds(1800), now.plusSeconds(43200))));
    }
    private void role(OrganizationMembership.Role role) {
        when(groups.lockOrganization(organization, true)).thenReturn(true);
        when(organizations.visibility(account, "LOGIN", organization)).thenReturn(Optional.of(
                new OrganizationRepository.Visibility(UUID.randomUUID(), role, 1, 1)));
    }
    @Test void pinCannotAdministerGroups() {
        caller(request); grant("PIN");
        assertThatThrownBy(() -> service.create(sid, account, organization, request)).isInstanceOf(GroupFailure.class)
                .extracting("status").isEqualTo(HttpStatus.FORBIDDEN);
        verifyNoInteractions(groups, organizations, outbox);
    }
    @Test void ordinaryOrganizationMemberCannotCreateGroups() {
        caller(request); grant("LOGIN"); role(OrganizationMembership.Role.MEMBER);
        assertThatThrownBy(() -> service.create(sid, account, organization, request)).isInstanceOf(GroupFailure.class);
        verify(groups, never()).create(any());
        verifyNoInteractions(outbox);
    }
    @Test void missingGrantCannotUseOrganizationMembershipAlone() {
        caller(request);
        assertThatThrownBy(() -> service.create(sid, account, organization, request)).isInstanceOf(GroupFailure.class);
        verifyNoInteractions(groups, organizations, outbox);
    }
    @Test void malformedNameIsRejectedBeforeAnyTransactionalWork() {
        GroupRequest invalid = new GroupRequest(account, UUID.randomUUID(), "Unsafe\nName", Group.Type.TEAM, null);
        when(validator.validate(invalid)).thenReturn(Set.of());
        assertThatThrownBy(() -> service.create(sid, account, organization, invalid)).isInstanceOf(GroupFailure.class)
                .extracting("status").isEqualTo(HttpStatus.BAD_REQUEST);
        verifyNoInteractions(access, groups, sessions, organizations, outbox);
    }
    @Test void hierarchyDepthLimitRejectsAnotherChild() {
        UUID parent = UUID.randomUUID();
        GroupRequest input = new GroupRequest(account, UUID.randomUUID(), "Child", Group.Type.CLASS, parent);
        caller(input); grant("LOGIN"); role(OrganizationMembership.Role.OWNER);
        GroupResponse response = new GroupResponse(parent, organization, null, "Parent", Group.Type.COURSE,
                Group.Status.ACTIVE, 1, now, now);
        when(groups.find(organization, parent)).thenReturn(Optional.of(new GroupRepository.Visible(response, 32)));
        assertThatThrownBy(() -> service.create(sid, account, organization, input)).isInstanceOf(GroupFailure.class)
                .extracting("status").isEqualTo(HttpStatus.BAD_REQUEST);
        verify(groups, never()).create(any());
        verifyNoInteractions(outbox);
    }
    @Test void requestIdCannotBeReusedForDifferentPayload() {
        caller(request); grant("LOGIN"); role(OrganizationMembership.Role.OWNER);
        when(groups.creation(organization, account, request.requestId())).thenReturn(Optional.of(
                new GroupRepository.Creation(UUID.randomUUID(), "0".repeat(64))));
        assertThatThrownBy(() -> service.create(sid, account, organization, request)).isInstanceOf(GroupFailure.class)
                .extracting("status").isEqualTo(HttpStatus.CONFLICT);
        verify(groups, never()).create(any());
        verifyNoInteractions(outbox);
    }

    @Test void canaryFailureDuringFinalRevalidationPreventsGroupCreation() {
        com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional =
                mock(com.unidocs.auth.authorization.application.ProfessionalAuthorizationService.class);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary =
                mock(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.class);
        @SuppressWarnings("unchecked") ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> provider =
                mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        service = new GroupService(groups, organizations, access, sessions, outbox, validator,
                new SimpleMeterRegistry(), professional, provider);
        caller(request); grant("LOGIN"); role(OrganizationMembership.Role.OWNER);
        when(professional.professional(organization)).thenReturn(true);
        when(canary.applies(organization)).thenReturn(true);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision =
                mock(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision.class);
        when(canary.check(sid, account, account, organization)).thenReturn(decision);
        when(decision.enforcing()).thenReturn(true);
        doThrow(new com.unidocs.auth.authorization.application.OperationAuthorizationFailure(
                HttpStatus.SERVICE_UNAVAILABLE, "SPICEDB_AUTHORIZATION_UNAVAILABLE"))
                .when(canary).revalidate(eq(decision), any(), eq(account), eq(organization));

        assertThatThrownBy(() -> service.create(sid, account, organization, request))
                .isInstanceOf(GroupFailure.class).extracting("status").isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        verify(groups, never()).create(any());
        verify(professional,never()).require(any(),any(),any(),any(),anyString(),anyString());
        verifyNoInteractions(outbox);
    }

    @Test void selectedGroupReadsCannotBypassAnUnavailableGraph() {
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary =
                mock(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.class);
        @SuppressWarnings("unchecked") ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> provider =
                mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(canary.applies(organization)).thenReturn(true);
        when(canary.check(sid,account,account,organization)).thenThrow(
                new com.unidocs.auth.authorization.application.OperationAuthorizationFailure(
                        HttpStatus.SERVICE_UNAVAILABLE,"SPICEDB_AUTHORIZATION_UNAVAILABLE"));
        service = new GroupService(groups,organizations,access,sessions,outbox,validator,
                new SimpleMeterRegistry(),mock(com.unidocs.auth.authorization.application.ProfessionalAuthorizationService.class),provider);

        assertThatThrownBy(() -> service.get(sid,account,account,organization,UUID.randomUUID()))
                .isInstanceOf(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class);
        assertThatThrownBy(() -> service.list(sid,account,account,organization,null,10))
                .isInstanceOf(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class);
        verifyNoInteractions(access,groups,outbox);
    }
}
