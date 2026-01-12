package com.unidocs.auth.credential.recovery.email;

import java.time.Clock;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import jakarta.validation.Validator;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.*;
import org.springframework.transaction.support.TransactionTemplate;
import com.unidocs.auth.registration.application.VerificationTokens;
import com.unidocs.auth.registration.application.RegistrationException;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.credential.application.PasswordChangeSecurity;
import com.unidocs.auth.outbox.persistence.OutboxRepository;

@Service
@Transactional(propagation=Propagation.NEVER)
public class EmailPasswordRecoveryService {
    private final EmailRecoveryRepository repository;
    private final SessionRepository sessions;
    private final PasswordChangeSecurity security;
    private final OutboxRepository outbox;
    private final PasswordEncoder passwords;
    private final ObjectProvider<EmailRecoveryDelivery> deliveries;
    private final VerificationTokens codes;
    private final Validator validator;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final MeterRegistry metrics;
    public EmailPasswordRecoveryService(EmailRecoveryRepository repository,SessionRepository sessions,PasswordChangeSecurity security,
            OutboxRepository outbox,PasswordEncoder passwords,ObjectProvider<EmailRecoveryDelivery> deliveries,
            VerificationTokens codes,Validator validator,PlatformTransactionManager manager,Clock clock,MeterRegistry metrics) {
        this.repository=repository;this.sessions=sessions;this.security=security;this.outbox=outbox;this.passwords=passwords;
        this.deliveries=deliveries;this.codes=codes;this.validator=validator;this.transactions=new TransactionTemplate(manager);this.clock=clock;this.metrics=metrics;
    }
    public void forgot(EmailRecoveryRequests.Forgot request) {
        validate(request);
        String email=request.email().strip().toLowerCase(Locale.ROOT);
        String code=codes.generate();String hash=codes.hash(code);
        EmailRecoveryDelivery delivery=deliveries.getIfAvailable();if(delivery==null) { count("request","unavailable");count("delivery","unavailable");return; }
        EmailRecoveryRepository.Target before=repository.target(email,request.accountId(),false).orElse(null);
        if(before==null) { count("request","ignored");return; }
        UUID reference=UUID.randomUUID();Instant now=clock.instant();
        String destination=transactions.execute(status->{
            sessions.lockGroup(before.groupId());
            EmailRecoveryRepository.Target current=repository.target(email,request.accountId(),true).orElse(null);
            if(current==null||!current.identityId().equals(before.identityId())||current.credentialVersion()!=before.credentialVersion()
                    ||!current.groupId().equals(before.groupId())||repository.throttled(current.identityId(),now))return null;
            repository.create(reference,current,hash,now);
            sessions.audit(current.userId(),current.accountId(),null,"PASSWORD_RECOVERY_REQUESTED",now);
            return current.email();
        });
        count("request",destination!=null?"issued":"ignored");
        if(destination!=null) {
            try { delivery.deliver(destination,reference,code,now.plusSeconds(300)); }
            catch(RuntimeException failure) { count("delivery","queue_rejected"); /* Do not expose delivery details. */ }
        }
    }
    public void reset(EmailRecoveryRequests.Reset request) {
        validate(request);
        EmailRecoveryRepository.Challenge before=repository.challenge(request.recoveryId(),false).orElse(null);
        boolean matched=codes.matches(request.code(),before==null?codes.hash("000000"):before.hash());
        String replacement=passwords.encode(request.newPassword());
        Boolean changed=transactions.execute(status->{
            if(before==null)return false;
            sessions.lockGroup(before.groupId());
            EmailRecoveryRepository.Target current=repository.target(before.email(),before.accountId(),true).orElse(null);
            EmailRecoveryRepository.Challenge challenge=repository.challenge(request.recoveryId(),true).orElse(null);
            if(current==null||challenge==null||!"PENDING".equals(challenge.status())||challenge.attempts()>=5
                    ||!challenge.identityId().equals(current.identityId())||challenge.version()!=current.credentialVersion()
                    ||!current.email().equals(challenge.email())
                    ||!current.groupId().equals(before.groupId())||!challenge.groupId().equals(before.groupId())||!challenge.hash().equals(before.hash()))return false;
            Instant now=clock.instant();
            if(!matched||!now.isBefore(challenge.expiresAt())) { repository.failed(challenge,now);return false; }
            repository.complete(challenge,current,replacement,now);
            security.revoke(current.accountId(),current.groupId(),current.userId(),now);
            sessions.audit(current.userId(),current.accountId(),null,"PASSWORD_RESET_COMPLETED",now);
            outbox.lifecycle("LOGIN_IDENTITY",current.identityId(),current.credentialVersion()+1,"PASSWORD_RESET_COMPLETED",current.accountId(),current.organizationId(),null,now);
            return true;
        });
        count("reset",Boolean.TRUE.equals(changed)?"succeeded":"rejected");
        if(!Boolean.TRUE.equals(changed))throw invalid();
    }
    private void count(String flow,String outcome) { metrics.counter("auth.password_recovery."+flow,"outcome",outcome).increment(); }
    private void validate(Object request) { if(request==null||!validator.validate(request).isEmpty())throw invalid(); }
    private static RegistrationException invalid() { return new RegistrationException(HttpStatus.BAD_REQUEST); }
}
