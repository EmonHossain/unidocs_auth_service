package com.unidocs.auth.organization.employee.recovery;
import java.util.*;
import java.time.Clock;
import java.security.SecureRandom;
import jakarta.validation.Validator;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.annotation.*;
import org.springframework.dao.DataIntegrityViolationException;
import com.unidocs.auth.organization.employee.EmployeeRepository;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.application.OrganizationFailure;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import com.unidocs.auth.credential.application.PasswordChangeSecurity;
import com.unidocs.auth.account.lifecycle.LifecycleRepository;
@Service
@Transactional(propagation=Propagation.NEVER)
public class EmployeeRecoveryService {
    private final EmployeeRecoveryRepository recoveries;
    private final EmployeeRepository employees;
    private final OrganizationRepository organizations;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final PasswordEncoder passwords;
    private final Validator validator;
    private final OutboxRepository outbox;
    private final OrganizationSnapshotStore snapshots;
    private final PasswordChangeSecurity changes;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final String dummy;
    private final MeterRegistry metrics;
    private final LifecycleRepository proofs;
    private final com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional;
    private final com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary;
    private record IssueResult(EmployeeRecoveryRequests.Pin pin) { }
    @Autowired
    public EmployeeRecoveryService(EmployeeRecoveryRepository recoveries,EmployeeRepository employees,OrganizationRepository organizations,
            SessionAccess access,SessionRepository sessions,PasswordEncoder passwords,Validator validator,OutboxRepository outbox,
            OrganizationSnapshotStore snapshots,PasswordChangeSecurity changes,PlatformTransactionManager manager,Clock clock,MeterRegistry metrics,LifecycleRepository proofs,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional,
            ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> canaryProvider) {
        this(recoveries,employees,organizations,access,sessions,passwords,validator,outbox,snapshots,changes,manager,clock,metrics,proofs,
                professional,canaryProvider.getIfAvailable());
    }
    public EmployeeRecoveryService(EmployeeRecoveryRepository recoveries,EmployeeRepository employees,OrganizationRepository organizations,
            SessionAccess access,SessionRepository sessions,PasswordEncoder passwords,Validator validator,OutboxRepository outbox,
            OrganizationSnapshotStore snapshots,PasswordChangeSecurity changes,PlatformTransactionManager manager,Clock clock,MeterRegistry metrics,LifecycleRepository proofs,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional) {
        this(recoveries,employees,organizations,access,sessions,passwords,validator,outbox,snapshots,changes,manager,clock,metrics,proofs,
                professional,(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary)null);
    }
    private EmployeeRecoveryService(EmployeeRecoveryRepository recoveries,EmployeeRepository employees,OrganizationRepository organizations,
            SessionAccess access,SessionRepository sessions,PasswordEncoder passwords,Validator validator,OutboxRepository outbox,
            OrganizationSnapshotStore snapshots,PasswordChangeSecurity changes,PlatformTransactionManager manager,Clock clock,MeterRegistry metrics,LifecycleRepository proofs,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary) {
        this.professional=professional;
        this.canary=canary;
        this.proofs=proofs;
        this.recoveries=recoveries;this.employees=employees;this.organizations=organizations;this.access=access;this.sessions=sessions;
        this.passwords=passwords;this.validator=validator;this.outbox=outbox;this.snapshots=snapshots;this.changes=changes;
        this.metrics=metrics;this.transactions=new TransactionTemplate(manager);this.clock=clock;this.dummy=passwords.encode(UUID.randomUUID().toString());
    }
    public void request(EmployeeRecoveryRequests.Forgot request) {
        validate(request);String username=normalize(request.username());
        metrics.counter("employee.password.recovery","outcome","request_accepted").increment();
        EmployeeRepository.Credential before=employees.credential(username,false).or(()->recoveries.legacyCredential(username)).orElse(null);
        if(before==null)return;
        try { transactions.executeWithoutResult(status->{
            sessions.lockGroup(before.groupId());if(sessions.owner(before.groupId()).isEmpty())return;employees.lockOrg(before.organizationId());
            EmployeeRepository.Credential current=employees.credential(username,true).orElse(null);
            if(current==null) {
                EmployeeRepository.Credential legacy=recoveries.legacyCredential(username).orElse(null);
                if(legacy==null||!legacy.groupId().equals(before.groupId())||!legacy.organizationId().equals(before.organizationId())||!employees.currentMember(legacy))return;
                recoveries.seedLegacy(legacy,clock.instant());current=employees.credential(username,true).orElse(null);
            }
            if(current==null||!current.accountId().equals(before.accountId())||!current.groupId().equals(before.groupId())||!employees.currentMember(current))return;
            if(recoveries.request(current.accountId(),current.organizationId(),request.requestId(),clock.instant())) {
                sessions.audit(employees.user(current.accountId()),current.accountId(),null,"EMPLOYEE_PASSWORD_RECOVERY_REQUESTED",clock.instant());
                outbox.lifecycle("EMPLOYEE_PASSWORD_RECOVERY",request.requestId(),1,"EMPLOYEE_PASSWORD_RECOVERY_REQUESTED",current.accountId(),current.organizationId(),null,clock.instant());
            }
        }); } catch(DataIntegrityViolationException conflict) { /* Same generic response for an existing request identifier. */ }
    }
    public List<EmployeeRecoveryRequests.View> list(UUID sid,UUID subject,UUID org,UUID adminAccount,UUID after,int limit) {
        if(adminAccount==null||limit<1||limit>100)throw new OrganizationFailure(HttpStatus.BAD_REQUEST);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=checkCanary(sid,subject,org,adminAccount);
        return access.execute(sid,subject,c->{admin(c,adminAccount,org,decision);if(decision!=null)canary.revalidate(decision,c,adminAccount,org);
            return recoveries.list(org,after,limit);});
    }
    public EmployeeRecoveryRequests.Pin issue(UUID sid,UUID subject,UUID org,UUID requestId,EmployeeRecoveryRequests.Issue request) {
        validate(request);if(!request.identityVerified())throw new OrganizationFailure(HttpStatus.BAD_REQUEST);
        EmployeeRecoveryRepository.Recovery before=recoveries.find(requestId,false).orElseThrow(EmployeeRecoveryService::denied);
        LifecycleRepository.Proof proof=proofs.proof(request.adminAccountId(),false).orElse(null);
        boolean matched=passwords.matches(request.password(),proof==null?dummy:proof.hash());
        String pin=String.format(java.util.Locale.ROOT,"%06d",new SecureRandom().nextInt(1_000_000));
        String hash=passwords.encode(pin),unusable=passwords.encode(UUID.randomUUID().toString());
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=
                checkCanary(sid,subject,org,request.adminAccountId());
        IssueResult result=access.executeForGroups(sid,subject,List.of(before.groupId()),c->{
            OrganizationMembership.Role actorRole=admin(c,request.adminAccountId(),org,decision);
            if(decision!=null)canary.revalidate(decision,c,request.adminAccountId(),org);
            EmployeeRecoveryRepository.Recovery current=recoveries.find(requestId,true).orElseThrow(EmployeeRecoveryService::denied);
            if(current.accountId().equals(request.adminAccountId())||employees.user(current.accountId()).equals(c.owner().userId())||!current.organizationId().equals(org)||!current.groupId().equals(before.groupId())||"COMPLETED".equals(current.status()))throw denied();
            EmployeeRepository.Credential credential=employees.credential(current.username(),true).orElseThrow(EmployeeRecoveryService::denied);
            if(!credential.accountId().equals(current.accountId())||!employees.currentMember(credential))throw denied();
            if(actorRole==OrganizationMembership.Role.ADMIN&&"OWNER".equals(recoveries.role(org,current.accountId())))throw denied();
            if(!proofs.verify(proof,matched,c.now()))return new IssueResult(null);
            recoveries.issue(current,hash,unusable,c.now());
            changes.revoke(current.accountId(),current.groupId(),employees.user(current.accountId()),c.now());
            long version=employees.changed(org,c.now());
            sessions.audit(c.owner().userId(),request.adminAccountId(),sid,"EMPLOYEE_RECOVERY_PIN_ISSUED",c.now());
            outbox.lifecycle("ORGANIZATION",org,version,"EMPLOYEE_RECOVERY_PIN_ISSUED",current.accountId(),org,null,c.now());
            return new IssueResult(new EmployeeRecoveryRequests.Pin(requestId,current.username(),pin));
        });
        if(result.pin()==null)throw denied();
        snapshots.invalidate(org,employees.version(org));metrics.counter("employee.password.recovery","outcome","pin_issued").increment();return result.pin();
    }
    public void reset(EmployeeRecoveryRequests.Reset request) {
        validate(request);EmployeeRecoveryRepository.Recovery before=recoveries.find(request.requestId(),false).orElse(null);
        boolean matched=passwords.matches(request.pin(),before==null||before.hash()==null?dummy:before.hash());
        String replacement=matched?passwords.encode(request.newPassword()):null;
        Boolean completed=transactions.execute(status->{
            if(before==null)return false;
            sessions.lockGroup(before.groupId());if(sessions.owner(before.groupId()).isEmpty())return false;employees.lockOrg(before.organizationId());
            EmployeeRecoveryRepository.Recovery current=recoveries.find(request.requestId(),true).orElse(null);
            if(current==null||!current.groupId().equals(before.groupId())||!current.username().equals(normalize(request.username()))||!"PIN_ISSUED".equals(current.status())||current.attempts()>=5)return false;
            EmployeeRepository.Credential credential=employees.credential(current.username(),true).orElse(null);
            if(credential==null||!credential.accountId().equals(current.accountId())||credential.version()!=current.version()||!employees.currentMember(credential))return false;
            if(!Objects.equals(before.hash(),current.hash())||before.version()!=current.version())return false;
            if(!matched) { recoveries.failed(current);return false; }
            recoveries.complete(current,replacement,clock.instant());
            changes.revoke(current.accountId(),current.groupId(),employees.user(current.accountId()),clock.instant());
            long version=employees.changed(current.organizationId(),clock.instant());
            sessions.audit(employees.user(current.accountId()),current.accountId(),null,"EMPLOYEE_PASSWORD_RESET_COMPLETED",clock.instant());
            outbox.lifecycle("ORGANIZATION",current.organizationId(),version,"EMPLOYEE_PASSWORD_RESET_COMPLETED",current.accountId(),current.organizationId(),null,clock.instant());return true;
        });
        if(!Boolean.TRUE.equals(completed)) { metrics.counter("employee.password.recovery","outcome","reset_failed").increment();throw new AuthenticationFailure(); }
        metrics.counter("employee.password.recovery","outcome","reset_completed").increment();
        snapshots.invalidate(before.organizationId(),employees.version(before.organizationId()));
    }
    private OrganizationMembership.Role admin(SessionAccess.Context context,UUID account,UUID org,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision) {
        if(organizations.university(org)) throw denied();
        SessionAccountGrant grant=sessions.liveGrant(context.session(),account,context.now()).orElseThrow(EmployeeRecoveryService::denied);
        if(!Set.of("LOGIN","PASSWORD").contains(grant.authMethod()))throw denied();employees.lockOrg(org);
        OrganizationRepository.Visibility visibility=organizations.visibility(account,grant.authMethod(),org).orElseThrow(EmployeeRecoveryService::denied);
        if(professional.professional(org)) {
            if(canary!=null)canary.requireDecision(org,null,"organization.employee.reset",decision);
            try { if(decision==null || !decision.enforcing())
                professional.require(context,account,org,null,"auth-service","organization.employee.reset"); }
            catch(com.unidocs.auth.authorization.application.OperationAuthorizationFailure failure) { throw new OrganizationFailure(failure.status()); }
            return visibility.role();
        }
        if(visibility.role()!=OrganizationMembership.Role.OWNER&&visibility.role()!=OrganizationMembership.Role.ADMIN)throw denied();
        return visibility.role();
    }
    private com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision checkCanary(
            UUID sid,UUID subject,UUID org,UUID account) {
        return canary!=null && canary.applies(org,"organization.employee.reset")
                ? canary.check(sid,subject,account,org,"organization.employee.reset"):null;
    }
    private void validate(Object request) { if(request==null||!validator.validate(request).isEmpty())throw new OrganizationFailure(HttpStatus.BAD_REQUEST); }
    private static String normalize(String username) { return username.strip().toLowerCase(Locale.ROOT); }
    private static OrganizationFailure denied() { return new OrganizationFailure(HttpStatus.FORBIDDEN); }
}
