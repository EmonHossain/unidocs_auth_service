package com.unidocs.auth.organization.application;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import com.unidocs.auth.account.domain.UserAccount;
import com.unidocs.auth.organization.api.OrganizationAccountRequest;
import com.unidocs.auth.organization.api.OrganizationAccountResponse;
import com.unidocs.auth.organization.domain.OrganizationInvitation;
import com.unidocs.auth.organization.persistence.InvitationRepository;
import com.unidocs.auth.organization.persistence.OrganizationAccountRepository;
import com.unidocs.auth.organization.persistence.OrganizationAccountRepository.Provisioned;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.application.SessionAccess.Context;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.domain.UserSession;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.session.persistence.SessionRepository.Owner;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OrganizationAccountServiceTests {
    @Mock OrganizationAccountRepository accounts;
    @Mock InvitationRepository invitations;
    @Mock OrganizationRepository organizations;
    @Mock SessionAccess access;
    @Mock SessionRepository sessions;
    @Mock InvitationTokens tokens;
    @Mock PasswordEncoder passwords;
    @Mock OutboxRepository outbox;
    @Mock Validator validator;
    @Mock MeterRegistry metrics;
    @Mock Counter counter;
    @Mock ConstraintViolation<OrganizationAccountRequest> violation;
    @InjectMocks OrganizationAccountService service;

    private final Instant now=Instant.parse("2026-10-02T12:00:00Z");
    private final UUID user=UUID.randomUUID();
    private final UUID source=UUID.randomUUID();
    private final UUID sid=UUID.randomUUID();
    private final UUID group=UUID.randomUUID();
    private final UUID org=UUID.randomUUID();
    private final UUID invitationId=UUID.randomUUID();
    private final OrganizationAccountRequest request=new OrganizationAccountRequest(source,"p".repeat(43)," Work ","independent-password");
    private final OrganizationAccountResponse response=new OrganizationAccountResponse(UUID.randomUUID(),org,UUID.randomUUID(),UserAccount.Type.UNIVERSITY,"Work");
    private final OrganizationInvitation invitation=new OrganizationInvitation(invitationId,org,UUID.randomUUID(),UUID.randomUUID(),1,"work@example.com","a".repeat(64),now);
    private Context context;
    private SessionAccountGrant grant;

    private OrganizationAccountResponse provision() { return service.provision(sid,source,org,invitationId,request); }
    private void givenCaller(String method,boolean retry) {
        when(validator.validate(request)).thenReturn(Set.of());
        if(!retry) {
            when(accounts.provisioned(invitationId)).thenReturn(Optional.empty());
            when(passwords.encode(request.password())).thenReturn("independent-hash");
        }
        grant=new SessionAccountGrant(sid,source,"ACTIVE",method,1,now.plusSeconds(1800),now.plusSeconds(43200));
        UserSession session=new UserSession(sid,group,source,"ACTIVE",now,now,now.plusSeconds(43200),null);
        context=new Context(session,new Owner(user,"Human",source),grant,now);
        when(access.execute(eq(sid),eq(source),any())).thenAnswer(call->{
            if(retry) verify(passwords).matches(request.password(),"independent-hash");
            else verify(passwords).encode(request.password());
            Function<Context,?> operation=call.getArgument(2);
            return operation.apply(context);
        });
        when(sessions.liveGrant(session,source,now)).thenReturn(Optional.of(grant));
    }
    private void givenInvitation(boolean issuerAvailable) {
        when(organizations.verifiedEmail(user)).thenReturn(Optional.of("personal@example.com"));
        when(invitations.lockUsableOrganization(org)).thenReturn(true);
        when(accounts.type(org)).thenReturn(com.unidocs.auth.organization.domain.Organization.Type.UNIVERSITY);
        when(invitations.userCanJoin(org,user)).thenReturn(true);
        when(invitations.lock(invitationId)).thenReturn(Optional.of(invitation));
        when(tokens.matches(request.token(),invitation.tokenHash())).thenReturn(true);
        if(invitation.status()==OrganizationInvitation.Status.PENDING) when(invitations.issuerCurrent(invitation)).thenReturn(issuerAvailable);
    }
    private void givenRetry(boolean passwordMatches) {
        invitation.acceptProvisioned(source,response.accountId(),response.membershipId(),now);
        givenCaller("LOGIN",true);
        givenInvitation(true);
        Provisioned snapshot=new Provisioned(response,user,group,UUID.randomUUID(),"independent-hash",1,true);
        when(accounts.provisioned(invitationId)).thenReturn(Optional.of(snapshot));
        when(passwords.matches(request.password(),"independent-hash")).thenReturn(passwordMatches);
    }

    @Test void invalidInputDoesNotHashPasswordsOrAccessSession() {
        when(validator.validate(request)).thenReturn(Set.of(violation));
        assertThatThrownBy(this::provision).isInstanceOfSatisfying(OrganizationFailure.class,e->assertThat(e.status()).isEqualTo(HttpStatus.BAD_REQUEST));
        verifyNoInteractions(passwords,accounts,access,invitations,outbox);
    }
    @Test void successfulProvisioningUsesIndependentHashAndPublishesOnlyAfterAccountCreation() {
        givenCaller("LOGIN",false); givenInvitation(true);
        when(accounts.create(context,source,org,"Work","independent-hash","work@example.com")).thenReturn(response);
        when(accounts.authorizationVersion(org)).thenReturn(2L);
        when(metrics.counter("organization.account.provision","outcome","succeeded")).thenReturn(counter);
        assertThat(provision()).isEqualTo(response);
        org.mockito.InOrder order=inOrder(accounts,invitations,outbox);
        order.verify(accounts).create(context,source,org,"Work","independent-hash","work@example.com");
        order.verify(invitations).flush();
        order.verify(outbox).invitationChanged(invitationId,org,2,"ACCEPTED",now);
        order.verify(outbox).accountProvisioned(response.accountId(),org,response.membershipId(),now);
        order.verify(outbox).membershipActivated(org,response.membershipId(),response.accountId(),invitationId,2,now);
        assertThat(invitation.provisioningAccountId()).isEqualTo(source);
        verify(sessions).touch(context.session(),grant,now);
        verify(counter).increment();
        verify(sessions,never()).create(any(),any(),any(),any());
    }
    @Test void pinGrantCannotAuthorizeProvisioning() {
        givenCaller("PIN",false);
        assertThatThrownBy(this::provision).isInstanceOfSatisfying(OrganizationFailure.class,e->assertThat(e.status()).isEqualTo(HttpStatus.FORBIDDEN));
        verifyNoInteractions(invitations,organizations,outbox);
        verify(accounts,never()).create(any(),any(),any(),any(),any(),any());
    }
    @Test void unavailableIssuerPreventsAccountAndOutboxWrites() {
        givenCaller("PASSWORD",false); givenInvitation(false);
        assertThatThrownBy(this::provision).isInstanceOf(OrganizationFailure.class);
        verify(accounts,never()).create(any(),any(),any(),any(),any(),any());
        verifyNoInteractions(outbox);
        assertThat(invitation.status()).isEqualTo(OrganizationInvitation.Status.PENDING);
    }
    @Test void existingHumanMembershipCannotBeBypassedByProvisioning() {
        givenCaller("LOGIN",false); givenInvitation(true);
        when(accounts.hasHumanMembership(org,user)).thenReturn(true);
        assertThatThrownBy(this::provision).isInstanceOfSatisfying(OrganizationFailure.class,e->assertThat(e.status()).isEqualTo(HttpStatus.CONFLICT));
        verify(accounts,never()).create(any(),any(),any(),any(),any(),any());
        verifyNoInteractions(outbox);
    }
    @Test void idempotentRetryVerifiesExistingPasswordAndCreatesNoAccountOrEvents() {
        givenRetry(true);
        when(metrics.counter("organization.account.provision","outcome","retried")).thenReturn(counter);
        assertThat(provision()).isEqualTo(response);
        verify(passwords,never()).encode(any());
        verify(accounts,never()).create(any(),any(),any(),any(),any(),any());
        verifyNoInteractions(outbox);
        verify(sessions).touch(context.session(),grant,now);
    }
    @Test void retryWithDifferentPasswordCannotReplaceCredentialOrConsumeInvitationAgain() {
        givenRetry(false);
        assertThatThrownBy(this::provision).isInstanceOfSatisfying(OrganizationFailure.class,e->assertThat(e.status()).isEqualTo(HttpStatus.CONFLICT));
        verify(passwords,never()).encode(any());
        verifyNoInteractions(outbox);
        verify(sessions,never()).touch(any(),any(),any());
        assertThat(invitation.version()).isEqualTo(2);
    }
}
