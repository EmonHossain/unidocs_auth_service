package com.unidocs.auth.organization.employee;
import java.util.UUID;
import java.util.Base64;
import java.util.Set;
import java.security.SecureRandom;
import java.time.Clock;
import jakarta.validation.Validator;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.annotation.*;
import org.springframework.dao.DataIntegrityViolationException;
import com.unidocs.auth.organization.application.OrganizationFailure;
import com.unidocs.auth.credential.application.PasswordChangeSecurity;
import com.unidocs.auth.account.lifecycle.LifecycleRepository;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.security.bruteforce.LoginAttackProtection;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
@Service
@Transactional(propagation=Propagation.NEVER)
public class EmployeeService {
    private final LoginAttackProtection protection;
    private final EmployeeRepository employees;
    private final OrganizationRepository organizations;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final PasswordEncoder passwords;
    private final Validator validator;
    private final OutboxRepository outbox;
    private final OrganizationSnapshotStore snapshots;
    private final AuthenticationService authentication;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final String dummy;
    private final PasswordChangeSecurity changes;
    private final LifecycleRepository proofs;
    private final com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional;
    private final com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary;
    private record ResetResult(EmployeeRequests.Credentials credentials) { }
    @Autowired
    public EmployeeService(EmployeeRepository employees,OrganizationRepository organizations,SessionAccess access,SessionRepository sessions,
            PasswordEncoder passwords,Validator validator,OutboxRepository outbox,OrganizationSnapshotStore snapshots,AuthenticationService authentication,
            PlatformTransactionManager manager,Clock clock,PasswordChangeSecurity changes,LoginAttackProtection protection,LifecycleRepository proofs,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional,
            ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> canaryProvider) {
        this(employees,organizations,access,sessions,passwords,validator,outbox,snapshots,authentication,manager,clock,changes,
                protection,proofs,professional,canaryProvider.getIfAvailable());
    }
    public EmployeeService(EmployeeRepository employees,OrganizationRepository organizations,SessionAccess access,SessionRepository sessions,
            PasswordEncoder passwords,Validator validator,OutboxRepository outbox,OrganizationSnapshotStore snapshots,AuthenticationService authentication,
            PlatformTransactionManager manager,Clock clock,PasswordChangeSecurity changes,LoginAttackProtection protection,LifecycleRepository proofs,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional) {
        this(employees,organizations,access,sessions,passwords,validator,outbox,snapshots,authentication,manager,clock,changes,
                protection,proofs,professional,(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary)null);
    }
    private EmployeeService(EmployeeRepository employees,OrganizationRepository organizations,SessionAccess access,SessionRepository sessions,
            PasswordEncoder passwords,Validator validator,OutboxRepository outbox,OrganizationSnapshotStore snapshots,AuthenticationService authentication,
            PlatformTransactionManager manager,Clock clock,PasswordChangeSecurity changes,LoginAttackProtection protection,LifecycleRepository proofs,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary) {
        this.professional=professional;
        this.canary=canary;
        this.proofs=proofs;
        this.protection=protection;this.employees=employees;this.organizations=organizations;this.access=access;this.sessions=sessions;this.passwords=passwords;this.validator=validator;
        this.outbox=outbox;this.snapshots=snapshots;this.authentication=authentication;this.transactions=new TransactionTemplate(manager);this.clock=clock;this.changes=changes;dummy=passwords.encode(UUID.randomUUID().toString());
    }
    public EmployeeRequests.Credentials create(UUID sid,UUID subject,UUID org,EmployeeRequests.Create request) {
        validate(request);String temporary=secret();String hash=passwords.encode(temporary);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision =
                canary != null && canary.applies(org,"organization.employee.create")
                        ? canary.check(sid,subject,request.adminAccountId(),org,"organization.employee.create") : null;
        try {
            EmployeeRequests.Credentials response=access.execute(sid,subject,c->{
                admin(c,request.adminAccountId(),org,"organization.employee.create",canaryDecision);String type=employees.type(org);
                if(canaryDecision!=null)canary.revalidate(canaryDecision,c,request.adminAccountId(),org);
                if("UNIVERSITY".equals(type))throw new OrganizationFailure(HttpStatus.BAD_REQUEST);
                EmployeeRequests.Credentials result=employees.create(org,type,request.displayName().strip(),"employee-"+UUID.randomUUID(),hash,request.adminAccountId(),request.requestId(),c.now(),temporary);
                long version=employees.changed(org,c.now());sessions.audit(c.owner().userId(),request.adminAccountId(),sid,"EMPLOYEE_PROVISIONED",c.now());
                outbox.membershipActivated(org,result.membershipId(),result.accountId(),request.requestId(),version,c.now());outbox.accountProvisioned(result.accountId(),org,result.membershipId(),c.now());return result;
            });
            snapshots.invalidate(org,employees.version(org));return response;
        } catch(DataIntegrityViolationException conflict) { throw new OrganizationFailure(HttpStatus.CONFLICT); }
    }
    public EmployeeRequests.Credentials reset(UUID sid,UUID subject,UUID org,UUID account,EmployeeRequests.Reset request) {
        validate(request);
        if(account.equals(request.adminAccountId()))throw denied();
        String username=employees.username(org,account).orElseThrow(EmployeeService::denied);
        EmployeeRepository.Credential before=employees.credential(username,false).orElseThrow(EmployeeService::denied);
        LifecycleRepository.Proof proof=proofs.proof(request.adminAccountId(),false).orElse(null);
        boolean matched=passwords.matches(request.password(),proof==null?dummy:proof.hash());
        String temporary=secret();String hash=passwords.encode(temporary);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision=
                canary!=null && canary.applies(org,"organization.employee.reset")
                        ? canary.check(sid,subject,request.adminAccountId(),org,"organization.employee.reset"):null;
        ResetResult result=access.executeForGroups(sid,subject,java.util.List.of(before.groupId()),c->{
            OrganizationMembership.Role actorRole=admin(c,request.adminAccountId(),org,"organization.employee.reset",canaryDecision);
            if(canaryDecision!=null)canary.revalidate(canaryDecision,c,request.adminAccountId(),org);
            EmployeeRepository.Credential current=employees.credential(username,true).orElseThrow(EmployeeService::denied);
            if(!current.groupId().equals(before.groupId())||!current.accountId().equals(account)||!current.organizationId().equals(org)
                    ||!employees.currentMember(current))throw denied();
            UUID targetUser=employees.user(account);
            if(targetUser.equals(c.owner().userId()))throw denied();
            OrganizationMembership.Role targetRole=organizations.activeMembershipRole(org,account).orElseThrow(EmployeeService::denied);
            if(actorRole==OrganizationMembership.Role.ADMIN&&targetRole==OrganizationMembership.Role.OWNER)throw denied();
            if(!proofs.verify(proof,matched,c.now()))return new ResetResult(null);
            employees.reset(account,hash,c.now());changes.revoke(account,current.groupId(),targetUser,c.now());
            long version=employees.changed(org,c.now());
            sessions.audit(c.owner().userId(),request.adminAccountId(),sid,"EMPLOYEE_CREDENTIAL_RESET",c.now());
            outbox.lifecycle("ORGANIZATION",org,version,"EMPLOYEE_CREDENTIAL_RESET",account,org,null,c.now());
            return new ResetResult(new EmployeeRequests.Credentials(account,employees.membership(org,account),username,temporary,true));
        });
        if(result.credentials()==null)throw denied();
        snapshots.invalidate(org,employees.version(org));return result.credentials();
    }
    public TokenResponse login(EmployeeRequests.Login request) {
        return login(request,"internal");
    }
    public TokenResponse login(EmployeeRequests.Login request,String peer) {
        if(request==null||!validator.validate(request).isEmpty())throw new AuthenticationFailure();
        String username=request.username().strip().toLowerCase(java.util.Locale.ROOT);
        EmployeeRepository.Credential before=employees.credential(username,false).orElse(null);
        String selector=before==null?"employee:"+username:"account:"+before.accountId();
        return protection.protect(peer,selector,()->authenticate(request,peer,username,before));
    }
    private TokenResponse authenticate(EmployeeRequests.Login request,String peer,String username,EmployeeRepository.Credential before) {
        boolean matched=passwords.matches(request.password(),before==null?dummy:before.hash());
        String replacement=before!=null&&before.pending()&&matched&&request.newPassword()!=null&&!request.newPassword().equals(request.password())?passwords.encode(request.newPassword()):null;
        UUID account=transactions.execute(status->{
            if(before==null)return null;
            sessions.lockGroup(before.groupId());if(sessions.owner(before.groupId()).isEmpty())return null;employees.lockOrg(before.organizationId());
            EmployeeRepository.Credential current=employees.credential(username,true).orElse(null);
            if(current==null||current.version()!=before.version()||!current.hash().equals(before.hash())||current.pending()!=before.pending()||!employees.currentMember(current))return null;
            if(!matched||current.attempts()>=5) { if(current.pending())employees.failed(current);return null; }
            if(current.pending()) {
                if(replacement==null)return null;
                employees.activate(current,replacement,clock.instant());
                sessions.audit(employees.user(current.accountId()),current.accountId(),null,"EMPLOYEE_ACTIVATED",clock.instant());
                outbox.lifecycle("USER_ACCOUNT",current.accountId(),current.version()+1,"EMPLOYEE_ACTIVATED",current.accountId(),current.organizationId(),null,clock.instant());
            } else if(request.newPassword()!=null)return null;
            return current.accountId();
        });
        if(account==null)throw new AuthenticationFailure();
        return authentication.loginAccount(account,new AccountLoginRequest(replacement==null?request.password():request.newPassword()),peer);
    }
    private OrganizationMembership.Role admin(SessionAccess.Context c,UUID account,UUID org,String operation,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision) {
        if(organizations.university(org)) throw denied();
        SessionAccountGrant grant=sessions.liveGrant(c.session(),account,c.now()).orElseThrow(EmployeeService::denied);
        if(!Set.of("LOGIN","PASSWORD").contains(grant.authMethod()))throw denied();employees.lockOrg(org);
        OrganizationRepository.Visibility visible=organizations.visibility(account,grant.authMethod(),org).orElseThrow(EmployeeService::denied);
        if(professional.professional(org)) {
            if(canary!=null)canary.requireDecision(org,null,operation,decision);
            try { if(decision==null || !decision.enforcing()) professional.require(c,account,org,null,"auth-service",operation); }
            catch(com.unidocs.auth.authorization.application.OperationAuthorizationFailure failure) { throw new OrganizationFailure(failure.status()); }
            return visible.role();
        }
        if(visible.role()!=OrganizationMembership.Role.OWNER&&visible.role()!=OrganizationMembership.Role.ADMIN)throw denied();
        return visible.role();
    }
    private void validate(Object request) { if(request==null||!validator.validate(request).isEmpty())throw new OrganizationFailure(HttpStatus.BAD_REQUEST); }
    private static String secret() { byte[] value=new byte[24];new SecureRandom().nextBytes(value);return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private static OrganizationFailure denied() { return new OrganizationFailure(HttpStatus.FORBIDDEN); }
}
