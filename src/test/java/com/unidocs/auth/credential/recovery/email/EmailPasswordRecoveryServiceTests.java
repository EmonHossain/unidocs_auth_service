package com.unidocs.auth.credential.recovery.email;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import java.util.Optional;
import java.util.Set;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import com.unidocs.auth.registration.application.*;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.credential.application.PasswordChangeSecurity;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;
@ExtendWith(MockitoExtension.class)
class EmailPasswordRecoveryServiceTests {
    @Mock EmailRecoveryRepository repository;
    @Mock SessionRepository sessions;
    @Mock PasswordChangeSecurity security;
    @Mock OutboxRepository outbox;
    @Mock PasswordEncoder passwords;
    @Mock ObjectProvider<EmailRecoveryDelivery> deliveries;
    @Mock EmailRecoveryDelivery delivery;
    @Mock VerificationTokens codes;
    @Mock Validator validator;
    @Mock PlatformTransactionManager manager;
    @Mock TransactionStatus transaction;
    EmailPasswordRecoveryService service;
    @BeforeEach void service() {
        service=new EmailPasswordRecoveryService(repository,sessions,security,outbox,passwords,deliveries,codes,validator,manager,Clock.systemUTC(),new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
    }
    @Test void missingAccountReturnsSameWithoutCreatingChallengeOrMutatingSecurity() {
        EmailRecoveryRequests.Forgot request=new EmailRecoveryRequests.Forgot("absent@example.com",null);
        when(validator.validate(request)).thenReturn(Set.of());when(codes.generate()).thenReturn("123456");when(codes.hash("123456")).thenReturn("hashed-code");
        when(deliveries.getIfAvailable()).thenReturn(delivery);when(repository.target("absent@example.com",null,false)).thenReturn(Optional.empty());
        service.forgot(request);
        verifyNoInteractions(delivery,security,outbox,manager);verify(repository,never()).create(any(),any(),anyString(),any());
    }
    @Test void sendsCodeOnlyToStoredVerifiedDestinationDespiteCollationAliasInput() {
        UUID identity=UUID.randomUUID(),account=UUID.randomUUID(),user=UUID.randomUUID(),group=UUID.randomUUID();
        EmailRecoveryRepository.Target target=new EmailRecoveryRepository.Target(identity,account,user,group,null,"verified@example.com","password-hash",1);
        EmailRecoveryRequests.Forgot request=new EmailRecoveryRequests.Forgot("vérified@example.com",null);
        when(validator.validate(request)).thenReturn(Set.of());when(codes.generate()).thenReturn("123456");when(codes.hash("123456")).thenReturn("hashed-code");
        when(deliveries.getIfAvailable()).thenReturn(delivery);
        when(repository.target("vérified@example.com",null,false)).thenReturn(Optional.of(target));
        when(repository.target("vérified@example.com",null,true)).thenReturn(Optional.of(target));
        when(manager.getTransaction(any())).thenReturn(transaction);
        service.forgot(request);
        verify(delivery).deliver(eq("verified@example.com"),any(UUID.class),eq("123456"),any(Instant.class));
        verify(delivery,never()).deliver(eq("vérified@example.com"),any(),anyString(),any());
    }
    @Test void mailboxReplacementCannotUseOldProofDespiteCollationEquivalentSelector() {
        UUID id=UUID.randomUUID(),account=UUID.randomUUID(),identity=UUID.randomUUID(),group=UUID.randomUUID();
        EmailRecoveryRepository.Challenge challenge=new EmailRecoveryRepository.Challenge(id,account,identity,group,"verified@example.com","hash",1,"PENDING",0,Instant.now().plusSeconds(300));
        EmailRecoveryRepository.Target target=new EmailRecoveryRepository.Target(identity,account,UUID.randomUUID(),group,null,"vérified@example.com","password-hash",1);
        EmailRecoveryRequests.Reset request=new EmailRecoveryRequests.Reset(id,"123456","new-password-long");
        when(validator.validate(request)).thenReturn(Set.of());when(repository.challenge(id,false)).thenReturn(Optional.of(challenge));
        when(codes.matches("123456","hash")).thenReturn(true);when(passwords.encode("new-password-long")).thenReturn("new-hash");
        when(manager.getTransaction(any())).thenReturn(transaction);when(repository.target("verified@example.com",account,true)).thenReturn(Optional.of(target));
        when(repository.challenge(id,true)).thenReturn(Optional.of(challenge));
        assertThatThrownBy(()->service.reset(request)).isInstanceOf(RegistrationException.class);
        verifyNoInteractions(security,outbox);verify(repository,never()).complete(any(),any(),anyString(),any());
    }
    @Test void staleCredentialVersionCannotResetEvenWithCorrectCode() {
        UUID id=UUID.randomUUID(),account=UUID.randomUUID(),identity=UUID.randomUUID(),group=UUID.randomUUID();
        EmailRecoveryRepository.Challenge challenge=new EmailRecoveryRepository.Challenge(id,account,identity,group,"user@example.com","hash",1,"PENDING",0,Instant.now().plusSeconds(300));
        EmailRecoveryRepository.Target target=new EmailRecoveryRepository.Target(identity,account,UUID.randomUUID(),group,null,"user@example.com","password-hash",2);
        EmailRecoveryRequests.Reset request=new EmailRecoveryRequests.Reset(id,"123456","new-password-long");
        when(validator.validate(request)).thenReturn(Set.of());when(repository.challenge(id,false)).thenReturn(Optional.of(challenge));
        when(codes.matches("123456","hash")).thenReturn(true);when(passwords.encode("new-password-long")).thenReturn("new-hash");
        when(manager.getTransaction(any())).thenReturn(transaction);when(repository.target("user@example.com",account,true)).thenReturn(Optional.of(target));
        when(repository.challenge(id,true)).thenReturn(Optional.of(challenge));
        assertThatThrownBy(()->service.reset(request)).isInstanceOf(RegistrationException.class);
        verifyNoInteractions(security,outbox);verify(repository,never()).complete(any(),any(),anyString(),any());
    }
    @Test void correctCodeAtExactExpiryIsRejectedAndMarkedExpired() {
        Instant now=Instant.parse("2026-10-08T12:00:00Z");
        service=new EmailPasswordRecoveryService(repository,sessions,security,outbox,passwords,deliveries,codes,validator,manager,
                Clock.fixed(now,java.time.ZoneOffset.UTC),new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
        UUID id=UUID.randomUUID(),account=UUID.randomUUID(),identity=UUID.randomUUID(),group=UUID.randomUUID();
        EmailRecoveryRepository.Challenge challenge=new EmailRecoveryRepository.Challenge(id,account,identity,group,"user@example.com","hash",1,"PENDING",0,now);
        EmailRecoveryRepository.Target target=new EmailRecoveryRepository.Target(identity,account,UUID.randomUUID(),group,null,"user@example.com","password-hash",1);
        EmailRecoveryRequests.Reset request=new EmailRecoveryRequests.Reset(id,"123456","new-password-long");
        stubReset(request,challenge,target,challenge);
        assertThatThrownBy(()->service.reset(request)).isInstanceOf(RegistrationException.class);
        verify(repository).failed(challenge,now);
        verify(repository,never()).complete(any(),any(),anyString(),any());verifyNoInteractions(security,outbox);
        verify(manager).commit(transaction);
    }
    @Test void proofChangedWhileHashWasCheckedCannotResetCredential() {
        UUID id=UUID.randomUUID(),account=UUID.randomUUID(),identity=UUID.randomUUID(),group=UUID.randomUUID();
        Instant expiry=Instant.now().plusSeconds(300);
        EmailRecoveryRepository.Challenge before=new EmailRecoveryRepository.Challenge(id,account,identity,group,"user@example.com","old-hash",1,"PENDING",0,expiry);
        EmailRecoveryRepository.Challenge current=new EmailRecoveryRepository.Challenge(id,account,identity,group,"user@example.com","replacement-hash",1,"PENDING",0,expiry);
        EmailRecoveryRepository.Target target=new EmailRecoveryRepository.Target(identity,account,UUID.randomUUID(),group,null,"user@example.com","password-hash",1);
        EmailRecoveryRequests.Reset request=new EmailRecoveryRequests.Reset(id,"123456","new-password-long");
        stubReset(request,before,target,current);
        assertThatThrownBy(()->service.reset(request)).isInstanceOf(RegistrationException.class);
        verify(repository,never()).complete(any(),any(),anyString(),any());
        verify(repository,never()).failed(any(),any());verifyNoInteractions(security,outbox);
    }
    @Test void fifthFailedAttemptObservedUnderLockRejectsPreviouslyMatchedProof() {
        UUID id=UUID.randomUUID(),account=UUID.randomUUID(),identity=UUID.randomUUID(),group=UUID.randomUUID();
        Instant expiry=Instant.now().plusSeconds(300);
        EmailRecoveryRepository.Challenge before=new EmailRecoveryRepository.Challenge(id,account,identity,group,"user@example.com","hash",1,"PENDING",4,expiry);
        EmailRecoveryRepository.Challenge locked=new EmailRecoveryRepository.Challenge(id,account,identity,group,"user@example.com","CONSUMED",1,"FAILED",5,expiry);
        EmailRecoveryRepository.Target target=new EmailRecoveryRepository.Target(identity,account,UUID.randomUUID(),group,null,"user@example.com","password-hash",1);
        EmailRecoveryRequests.Reset request=new EmailRecoveryRequests.Reset(id,"123456","new-password-long");
        stubReset(request,before,target,locked);
        assertThatThrownBy(()->service.reset(request)).isInstanceOf(RegistrationException.class);
        verify(repository,never()).complete(any(),any(),anyString(),any());
        verify(repository,never()).failed(any(),any());verifyNoInteractions(security,outbox);
    }
    @Test void verifiedResetRecordsAuditWithinCredentialTransaction() {
        Instant now=Instant.parse("2026-10-09T12:00:00Z");
        service=new EmailPasswordRecoveryService(repository,sessions,security,outbox,passwords,deliveries,codes,validator,manager,
                Clock.fixed(now,java.time.ZoneOffset.UTC),new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
        UUID id=UUID.randomUUID(),account=UUID.randomUUID(),identity=UUID.randomUUID(),group=UUID.randomUUID(),user=UUID.randomUUID();
        EmailRecoveryRepository.Challenge challenge=new EmailRecoveryRepository.Challenge(id,account,identity,group,"user@example.com","hash",1,"PENDING",0,now.plusSeconds(300));
        EmailRecoveryRepository.Target target=new EmailRecoveryRepository.Target(identity,account,user,group,null,"user@example.com","password-hash",1);
        EmailRecoveryRequests.Reset request=new EmailRecoveryRequests.Reset(id,"123456","new-password-long");
        stubReset(request,challenge,target,challenge);
        service.reset(request);
        org.mockito.InOrder order=inOrder(repository,sessions,manager);
        order.verify(repository).complete(challenge,target,"new-hash",now);
        order.verify(sessions).audit(user,account,null,"PASSWORD_RESET_COMPLETED",now);
        order.verify(manager).commit(transaction);
    }
    @Test void auditFailureRollsBackVerifiedReset() {
        Instant now=Instant.parse("2026-10-09T12:00:00Z");
        service=new EmailPasswordRecoveryService(repository,sessions,security,outbox,passwords,deliveries,codes,validator,manager,
                Clock.fixed(now,java.time.ZoneOffset.UTC),new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
        UUID id=UUID.randomUUID(),account=UUID.randomUUID(),identity=UUID.randomUUID(),group=UUID.randomUUID(),user=UUID.randomUUID();
        EmailRecoveryRepository.Challenge challenge=new EmailRecoveryRepository.Challenge(id,account,identity,group,"user@example.com","hash",1,"PENDING",0,now.plusSeconds(300));
        EmailRecoveryRepository.Target target=new EmailRecoveryRepository.Target(identity,account,user,group,null,"user@example.com","password-hash",1);
        EmailRecoveryRequests.Reset request=new EmailRecoveryRequests.Reset(id,"123456","new-password-long");
        stubReset(request,challenge,target,challenge);
        doThrow(new IllegalStateException("audit unavailable")).when(sessions).audit(user,account,null,"PASSWORD_RESET_COMPLETED",now);
        assertThatThrownBy(()->service.reset(request)).isInstanceOf(IllegalStateException.class).hasMessage("audit unavailable");
        verify(manager).rollback(transaction);
        verify(manager,never()).commit(transaction);
    }
    private void stubReset(EmailRecoveryRequests.Reset request,EmailRecoveryRepository.Challenge before,
            EmailRecoveryRepository.Target target,EmailRecoveryRepository.Challenge current) {
        when(validator.validate(request)).thenReturn(Set.of());
        when(repository.challenge(request.recoveryId(),false)).thenReturn(Optional.of(before));
        when(codes.matches(request.code(),before.hash())).thenReturn(true);
        when(passwords.encode(request.newPassword())).thenReturn("new-hash");
        when(manager.getTransaction(any())).thenReturn(transaction);
        when(repository.target(before.email(),before.accountId(),true)).thenReturn(Optional.of(target));
        when(repository.challenge(request.recoveryId(),true)).thenReturn(Optional.of(current));
    }

}
