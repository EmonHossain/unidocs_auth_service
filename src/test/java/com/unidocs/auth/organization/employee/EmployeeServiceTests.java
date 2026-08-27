package com.unidocs.auth.organization.employee;
import java.util.UUID;
import java.util.Optional;
import java.util.Set;
import java.time.Clock;
import java.util.function.Supplier;
import com.unidocs.auth.security.bruteforce.LoginAttackProtection;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.http.HttpStatus;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.authentication.api.TokenResponse;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;
@ExtendWith(MockitoExtension.class)
class EmployeeServiceTests {
    /**
     * Prevents provisioning and credential replacement when final graph revalidation fails.
     * @param reset whether the entry point replaces credentials rather than provisioning
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void finalGraphDenialCannotProvisionOrReplaceEmployeeCredentials(boolean reset) {
        UUID sid = UUID.randomUUID(), subject = UUID.randomUUID(), org = UUID.randomUUID();
        UUID admin = UUID.randomUUID(), target = UUID.randomUUID(), group = UUID.randomUUID();
        java.time.Instant now = java.time.Instant.parse("2026-10-31T12:00:00Z");
        String operation = reset ? "organization.employee.reset" : "organization.employee.create";
        SessionAccess.Context context = mock(SessionAccess.Context.class);
        when(context.now()).thenReturn(now);
        com.unidocs.auth.session.domain.SessionAccountGrant grant = mock(com.unidocs.auth.session.domain.SessionAccountGrant.class);
        when(grant.authMethod()).thenReturn("LOGIN");
        when(sessions.liveGrant(null, admin, now)).thenReturn(Optional.of(grant));
        when(organizations.visibility(admin, "LOGIN", org)).thenReturn(Optional.of(new OrganizationRepository.Visibility(
                UUID.randomUUID(), com.unidocs.auth.organization.domain.OrganizationMembership.Role.OWNER, 1, 1)));
        com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional =
                mock(com.unidocs.auth.authorization.application.ProfessionalAuthorizationService.class);
        when(professional.professional(org)).thenReturn(true);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary =
                mock(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.class);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision =
                mock(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision.class);
        @SuppressWarnings("unchecked") org.springframework.beans.factory.ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> provider =
                mock(org.springframework.beans.factory.ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(canary.applies(org, operation)).thenReturn(true);
        when(canary.check(sid, subject, admin, org, operation)).thenReturn(decision);
        when(decision.enforcing()).thenReturn(true);
        when(canary.revalidate(decision, context, admin, org)).thenThrow(
                new com.unidocs.auth.authorization.application.OperationAuthorizationFailure(
                        HttpStatus.SERVICE_UNAVAILABLE, "SPICEDB_AUTHORIZATION_UNAVAILABLE"));
        com.unidocs.auth.credential.application.PasswordChangeSecurity changes =
                mock(com.unidocs.auth.credential.application.PasswordChangeSecurity.class);
        EmployeeService guarded = new EmployeeService(employees, organizations, access, sessions, passwords, validator,
                outbox, snapshots, authentication, manager, Clock.systemUTC(), changes, protection, proofs, professional, provider);
        if (reset) {
            when(employees.username(org, target)).thenReturn(Optional.of("synthetic-employee"));
            when(employees.credential("synthetic-employee", false)).thenReturn(Optional.of(
                    new EmployeeRepository.Credential(target, org, group, "synthetic-employee", "hash", 1, false, 0)));
            when(access.executeForGroups(eq(sid), eq(subject), eq(java.util.List.of(group)), any())).thenAnswer(call ->
                    call.<java.util.function.Function<SessionAccess.Context, Object>>getArgument(3).apply(context));
            assertThatThrownBy(() -> guarded.reset(sid, subject, org, target, new EmployeeRequests.Reset(admin, "proof")))
                    .isInstanceOf(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class);
        } else {
            when(employees.type(org)).thenReturn("COMPANY");
            when(access.execute(eq(sid), eq(subject), any())).thenAnswer(call ->
                    call.<java.util.function.Function<SessionAccess.Context, Object>>getArgument(2).apply(context));
            assertThatThrownBy(() -> guarded.create(sid, subject, org,
                    new EmployeeRequests.Create(admin, UUID.randomUUID(), "Synthetic Employee")))
                    .isInstanceOf(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class);
        }
        verify(employees, never()).create(any(), anyString(), anyString(), anyString(), anyString(), any(), any(), any(), anyString());
        verify(employees, never()).reset(any(), anyString(), any());
        verify(employees, never()).changed(any(), any());
        verify(professional, never()).require(any(), any(), any(), any(), anyString(), anyString());
        verify(sessions, never()).audit(any(), any(), any(), anyString(), any());
        verifyNoInteractions(outbox, snapshots, changes);
    }

    @Mock LoginAttackProtection protection;
    @Mock EmployeeRepository employees;
    @Mock OrganizationRepository organizations;
    @Mock SessionAccess access;
    @Mock SessionRepository sessions;
    @Mock PasswordEncoder passwords;
    @Mock com.unidocs.auth.account.lifecycle.LifecycleRepository proofs;
    @Mock Validator validator;
    @Mock OutboxRepository outbox;
    @Mock OrganizationSnapshotStore snapshots;
    @Mock AuthenticationService authentication;
    @Mock PlatformTransactionManager manager;
    @Mock TransactionStatus transaction;
    EmployeeService service;
    @BeforeEach void service() {
        when(passwords.encode(anyString())).thenReturn("dummy-hash");
        service=new EmployeeService(employees,organizations,access,sessions,passwords,validator,outbox,snapshots,authentication,manager,Clock.systemUTC(),mock(com.unidocs.auth.credential.application.PasswordChangeSecurity.class),protection,proofs,mock(com.unidocs.auth.authorization.application.ProfessionalAuthorizationService.class));
        lenient().when(protection.protect(anyString(),anyString(),any())).thenAnswer(invocation -> invocation.<Supplier<TokenResponse>>getArgument(2).get());
    }
    @Test void unknownUsernameDoesDummyPasswordCheckButCannotIssueSession() {
        EmployeeRequests.Login request=new EmployeeRequests.Login("unknown","password-long",null);
        when(validator.validate(request)).thenReturn(Set.of());when(employees.credential("unknown",false)).thenReturn(Optional.empty());
        when(manager.getTransaction(any())).thenReturn(transaction);
        assertThatThrownBy(()->service.login(request)).isInstanceOf(AuthenticationFailure.class);
        verify(passwords).matches("password-long","dummy-hash");verifyNoInteractions(authentication);verify(employees,never()).activate(any(),anyString(),any());
    }
    @Test void blockedEmployeeCannotCheckPasswordOrActivate() {
        EmployeeRequests.Login request=new EmployeeRequests.Login(" EMPLOYEE ","temporary-password","replacement-password");
        when(validator.validate(request)).thenReturn(Set.of());
        UUID account=UUID.randomUUID();
        EmployeeRepository.Credential credential=new EmployeeRepository.Credential(account,UUID.randomUUID(),UUID.randomUUID(),"employee","hash",1,true,0);
        when(employees.credential("employee",false)).thenReturn(Optional.of(credential));
        when(protection.protect(eq("192.0.2.1"),eq("account:"+account),any())).thenThrow(new AuthenticationFailure());
        assertThatThrownBy(()->service.login(request,"192.0.2.1")).isInstanceOf(AuthenticationFailure.class);
        verify(passwords,never()).matches(anyString(),anyString());
        verify(employees,never()).activate(any(),anyString(),any());
        verifyNoInteractions(manager,authentication,outbox);
    }
    @Test void pendingCredentialWithoutReplacementCannotActivateOrIssueSession() {
        UUID account=UUID.randomUUID(),org=UUID.randomUUID(),group=UUID.randomUUID();
        EmployeeRepository.Credential pending=new EmployeeRepository.Credential(account,org,group,"employee","temporary-hash",1,true,0);
        EmployeeRequests.Login request=new EmployeeRequests.Login("employee","temporary-password",null);
        when(validator.validate(request)).thenReturn(Set.of());when(employees.credential("employee",false)).thenReturn(Optional.of(pending));
        when(passwords.matches("temporary-password","temporary-hash")).thenReturn(true);when(manager.getTransaction(any())).thenReturn(transaction);
        when(sessions.owner(group)).thenReturn(Optional.of(new SessionRepository.Owner(UUID.randomUUID(),"Employee",account)));
        when(employees.credential("employee",true)).thenReturn(Optional.of(pending));when(employees.currentMember(pending)).thenReturn(true);
        assertThatThrownBy(()->service.login(request)).isInstanceOf(AuthenticationFailure.class);
        verifyNoInteractions(authentication);verify(employees,never()).activate(any(),anyString(),any());verifyNoInteractions(outbox);
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
        EmployeeRequests.Reset request=new EmployeeRequests.Reset(admin,"admin-password");
        when(validator.validate(request)).thenReturn(Set.of());
        when(employees.username(org,account)).thenReturn(Optional.of("employee"));
        when(employees.credential("employee",false)).thenReturn(Optional.of(new EmployeeRepository.Credential(account,org,group,"employee","old-hash",1,false,0)));
        UUID targetUser=UUID.randomUUID();
        when(context.owner()).thenReturn(new SessionRepository.Owner(UUID.randomUUID(),"Owner",UUID.randomUUID()));
        when(employees.user(account)).thenReturn(targetUser);
        EmployeeRepository.Credential current=new EmployeeRepository.Credential(account,org,group,"employee","old-hash",1,false,0);
        when(employees.credential("employee",true)).thenReturn(Optional.of(current));
        when(employees.currentMember(current)).thenReturn(true);
        when(organizations.activeMembershipRole(org,account)).thenReturn(Optional.of(com.unidocs.auth.organization.domain.OrganizationMembership.Role.MEMBER));
        assertThatThrownBy(()->service.reset(UUID.randomUUID(),UUID.randomUUID(),org,account,request)).isInstanceOf(com.unidocs.auth.organization.application.OrganizationFailure.class);
        verify(proofs).verify(proof,matched,now);
        verify(employees,never()).reset(any(),anyString(),any());
        verifyNoInteractions(outbox,snapshots);
    }

    @Test void administratorPasswordIsRedacted() {
        assertThat(new EmployeeRequests.Reset(UUID.randomUUID(),"admin-password").toString()).doesNotContain("admin-password");
    }

    @Test void deniedEmployeeCreateCanaryDoesNotStartProvisioning() {
        UUID session=UUID.randomUUID(),subject=UUID.randomUUID(),organization=UUID.randomUUID(),admin=UUID.randomUUID();
        EmployeeRequests.Create request=new EmployeeRequests.Create(admin,UUID.randomUUID(),"New Employee");
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary=
                mock(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.class);
        @SuppressWarnings("unchecked") org.springframework.beans.factory.ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> provider=
                mock(org.springframework.beans.factory.ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(canary.applies(organization,"organization.employee.create")).thenReturn(true);
        when(canary.check(session,subject,admin,organization,"organization.employee.create"))
                .thenThrow(new com.unidocs.auth.authorization.application.OperationAuthorizationFailure(
                        org.springframework.http.HttpStatus.FORBIDDEN,"PROFESSIONAL_AUTHORITY_DENIED"));
        when(validator.validate(request)).thenReturn(Set.of());
        EmployeeService guarded=new EmployeeService(employees,organizations,access,sessions,passwords,validator,outbox,
                snapshots,authentication,manager,Clock.systemUTC(),
                mock(com.unidocs.auth.credential.application.PasswordChangeSecurity.class),protection,proofs,
                mock(com.unidocs.auth.authorization.application.ProfessionalAuthorizationService.class),provider);
        assertThatThrownBy(()->guarded.create(session,subject,organization,request))
                .isInstanceOf(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class);
        verifyNoInteractions(access,outbox,employees);
    }
}
