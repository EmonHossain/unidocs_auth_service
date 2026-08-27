package com.unidocs.auth.organization.employee.recovery;
import java.util.*;
import java.time.Clock;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import com.unidocs.auth.organization.employee.EmployeeRepository;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.organization.application.OrganizationFailure;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import com.unidocs.auth.credential.application.PasswordChangeSecurity;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;
@ExtendWith(MockitoExtension.class)
class EmployeeRecoveryServiceTests {
    /**
     * Blocks recovery metadata and factor issuance after final graph revalidation fails.
     * @param issue whether to exercise factor issuance instead of the administrative list
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void staleGraphDecisionCannotListRecoveryRequestsOrIssueFactors(boolean issue) {
        UUID sid = UUID.randomUUID(), subject = UUID.randomUUID(), organization = UUID.randomUUID();
        UUID admin = UUID.randomUUID(), group = UUID.randomUUID(), request = UUID.randomUUID();
        java.time.Instant now = java.time.Instant.parse("2026-10-31T12:00:00Z");
        SessionAccess.Context context = mock(SessionAccess.Context.class);
        when(context.now()).thenReturn(now);
        com.unidocs.auth.session.domain.SessionAccountGrant grant = mock(com.unidocs.auth.session.domain.SessionAccountGrant.class);
        when(grant.authMethod()).thenReturn("LOGIN");
        when(sessions.liveGrant(null, admin, now)).thenReturn(Optional.of(grant));
        when(organizations.visibility(admin, "LOGIN", organization)).thenReturn(Optional.of(new OrganizationRepository.Visibility(
                UUID.randomUUID(), com.unidocs.auth.organization.domain.OrganizationMembership.Role.OWNER, 1, 1)));
        com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional =
                mock(com.unidocs.auth.authorization.application.ProfessionalAuthorizationService.class);
        when(professional.professional(organization)).thenReturn(true);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary =
                mock(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.class);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision =
                mock(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision.class);
        @SuppressWarnings("unchecked") org.springframework.beans.factory.ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> provider =
                mock(org.springframework.beans.factory.ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(canary.applies(organization, "organization.employee.reset")).thenReturn(true);
        when(canary.check(sid, subject, admin, organization, "organization.employee.reset")).thenReturn(decision);
        when(decision.enforcing()).thenReturn(true);
        when(canary.revalidate(decision, context, admin, organization)).thenThrow(
                new com.unidocs.auth.authorization.application.OperationAuthorizationFailure(
                        org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE, "SPICEDB_AUTHORIZATION_UNAVAILABLE"));
        EmployeeRecoveryService guarded = new EmployeeRecoveryService(recoveries, employees, organizations, access,
                sessions, passwords, validator, outbox, snapshots, changes, manager, Clock.systemUTC(),
                new io.micrometer.core.instrument.simple.SimpleMeterRegistry(), proofs, professional, provider);
        if (issue) {
            when(recoveries.find(request, false)).thenReturn(Optional.of(new EmployeeRecoveryRepository.Recovery(
                    request, UUID.randomUUID(), organization, group, "synthetic-employee", "PENDING", null, 1, 0)));
            when(access.executeForGroups(eq(sid), eq(subject), eq(List.of(group)), any())).thenAnswer(call ->
                    call.<java.util.function.Function<SessionAccess.Context, Object>>getArgument(3).apply(context));
            assertThatThrownBy(() -> guarded.issue(sid, subject, organization, request,
                    new EmployeeRecoveryRequests.Issue(admin, true, "proof")))
                    .isInstanceOf(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class);
            verify(recoveries, never()).find(request, true);
        } else {
            when(access.execute(eq(sid), eq(subject), any())).thenAnswer(call ->
                    call.<java.util.function.Function<SessionAccess.Context, Object>>getArgument(2).apply(context));
            assertThatThrownBy(() -> guarded.list(sid, subject, organization, admin, null, 10))
                    .isInstanceOf(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class);
        }
        verify(recoveries, never()).issue(any(), anyString(), anyString(), any());
        verify(recoveries, never()).list(any(), any(), anyInt());
        verify(professional, never()).require(any(), any(), any(), any(), anyString(), anyString());
        verify(sessions, never()).audit(any(), any(), any(), anyString(), any());
        verifyNoInteractions(changes, outbox, snapshots);
    }

    @Mock EmployeeRecoveryRepository recoveries;
    @Mock EmployeeRepository employees;
    @Mock OrganizationRepository organizations;
    @Mock SessionAccess access;
    @Mock SessionRepository sessions;
    @Mock PasswordEncoder passwords;
    @Mock com.unidocs.auth.account.lifecycle.LifecycleRepository proofs;
    @Mock Validator validator;
    @Mock OutboxRepository outbox;
    @Mock OrganizationSnapshotStore snapshots;
    @Mock PasswordChangeSecurity changes;
    @Mock PlatformTransactionManager manager;
    EmployeeRecoveryService service;
    @BeforeEach void initialize() {
        when(passwords.encode(anyString())).thenReturn("dummy-hash");
        service=new EmployeeRecoveryService(recoveries,employees,organizations,access,sessions,passwords,validator,outbox,snapshots,changes,manager,Clock.systemUTC(),new io.micrometer.core.instrument.simple.SimpleMeterRegistry(),proofs,mock(com.unidocs.auth.authorization.application.ProfessionalAuthorizationService.class));
    }
    @Test void unknownUsernameNeverDisablesIdentityOrCreatesAdminRequest() {
        EmployeeRecoveryRequests.Forgot request=new EmployeeRecoveryRequests.Forgot("UNKNOWN",UUID.randomUUID());
        when(validator.validate(request)).thenReturn(Set.of());when(employees.credential("unknown",false)).thenReturn(Optional.empty());when(recoveries.legacyCredential("unknown")).thenReturn(Optional.empty());
        service.request(request);verify(recoveries).legacyCredential("unknown");verifyNoInteractions(sessions,outbox,changes,manager);verify(recoveries,never()).request(any(),any(),any(),any());
    }
    @Test void AdministratorMustConfirmTrustedIdentityCheckBeforeIssuingPin() {
        EmployeeRecoveryRequests.Issue request=new EmployeeRecoveryRequests.Issue(UUID.randomUUID(),false,"admin-password");
        when(validator.validate(request)).thenReturn(Set.of());
        assertThatThrownBy(()->service.issue(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),request)).isInstanceOf(OrganizationFailure.class);
        verifyNoInteractions(recoveries,employees,access,changes,outbox);
    }
    @Test void secretDtosNeverPrintPinOrPassword() {
        EmployeeRecoveryRequests.Reset request=new EmployeeRecoveryRequests.Reset("employee",UUID.randomUUID(),"123456","new-password-long");
        assertThat(request.toString()).doesNotContain("123456","new-password-long");
        assertThat(new EmployeeRecoveryRequests.Pin(UUID.randomUUID(),"employee","123456").toString()).doesNotContain("123456");
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans={false,true})
    void invalidOrChangedCurrentPasswordCannotResetCredentials(boolean matched) {
        UUID admin=UUID.randomUUID(),account=UUID.randomUUID(),org=UUID.randomUUID(),group=UUID.randomUUID();
        java.time.Instant now=java.time.Instant.parse("2026-10-08T12:00:00Z");
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        when(context.now()).thenReturn(now);
        com.unidocs.auth.session.domain.SessionAccountGrant grant=mock(com.unidocs.auth.session.domain.SessionAccountGrant.class);
        when(grant.authMethod()).thenReturn("LOGIN");
        when(sessions.liveGrant(null,admin,now)).thenReturn(Optional.of(grant));
        when(organizations.visibility(admin,"LOGIN",org)).thenReturn(Optional.of(new OrganizationRepository.Visibility(UUID.randomUUID(),com.unidocs.auth.organization.domain.OrganizationMembership.Role.OWNER,1,1)));
        com.unidocs.auth.account.lifecycle.LifecycleRepository.Proof proof=new com.unidocs.auth.account.lifecycle.LifecycleRepository.Proof(UUID.randomUUID(),admin,"admin-hash",1,0,null);
        when(proofs.proof(admin,false)).thenReturn(Optional.of(proof));
        when(passwords.matches("admin-password","admin-hash")).thenReturn(matched);
        when(proofs.verify(proof,matched,now)).thenReturn(false);
        when(access.executeForGroups(any(),any(),anyList(),any())).thenAnswer(invocation -> invocation.<java.util.function.Function<SessionAccess.Context,Object>>getArgument(3).apply(context));
        UUID requestId=UUID.randomUUID();
        EmployeeRecoveryRequests.Issue request=new EmployeeRecoveryRequests.Issue(admin,true,"admin-password");
        when(validator.validate(request)).thenReturn(Set.of());
        when(recoveries.find(requestId,false)).thenReturn(Optional.of(new EmployeeRecoveryRepository.Recovery(requestId,account,org,group,"employee","REQUESTED",null,1,0)));
        UUID targetUser=UUID.randomUUID();
        when(context.owner()).thenReturn(new SessionRepository.Owner(UUID.randomUUID(),"Owner",UUID.randomUUID()));
        when(employees.user(account)).thenReturn(targetUser);
        EmployeeRepository.Credential current=new EmployeeRepository.Credential(account,org,group,"employee","old-hash",1,false,0);
        when(employees.credential("employee",true)).thenReturn(Optional.of(current));
        when(employees.currentMember(current)).thenReturn(true);
        when(recoveries.find(requestId,true)).thenReturn(Optional.of(new EmployeeRecoveryRepository.Recovery(requestId,account,org,group,"employee","REQUESTED",null,1,0)));
        assertThatThrownBy(()->service.issue(UUID.randomUUID(),UUID.randomUUID(),org,requestId,request)).isInstanceOf(com.unidocs.auth.organization.application.OrganizationFailure.class);
        verify(proofs).verify(proof,matched,now);
        verify(recoveries,never()).issue(any(),anyString(),anyString(),any());
        verifyNoInteractions(changes);
        verifyNoInteractions(outbox,snapshots);
    }

    @Test void administratorPasswordIsRedacted() {
        assertThat(new EmployeeRecoveryRequests.Issue(UUID.randomUUID(),true,"admin-password").toString()).doesNotContain("admin-password");
    }
}
