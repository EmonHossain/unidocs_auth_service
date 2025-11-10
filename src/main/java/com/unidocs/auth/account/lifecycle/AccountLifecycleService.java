package com.unidocs.auth.account.lifecycle;

import java.time.Clock;
import java.time.Instant;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.support.TransactionTemplate;
import io.micrometer.core.instrument.MeterRegistry;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import com.unidocs.auth.organization.domain.OrganizationMembership.Role;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.application.SessionAccess.Context;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.account.lifecycle.LifecycleRepository.*;

@Service
@Transactional(propagation=Propagation.NEVER)
public class AccountLifecycleService {
    public record Options(List<Account> accounts,boolean selectionRequired,UUID nextCursor) { }
    public record Result(UUID accountId,String status,Instant retainUntil,UUID noticeId,UUID removalRequestId) { }
    public record Page<T>(List<T> items,UUID nextCursor) { }
    private final LifecycleRepository store;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final OrganizationRepository organizations;
    private final OrganizationSnapshotStore snapshots;
    private final OutboxRepository outbox;
    private final RetentionPolicy retention;
    private final AccountNoticeDelivery delivery;
    private final PasswordEncoder passwords;
    private final Clock clock;
    private final MeterRegistry metrics;
    private final String dummyHash;
    private final TransactionTemplate transactions;
    private final com.unidocs.auth.group.personal.PersonalAccountDeparture personalDeparture;
    private final com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional;
    private final com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary;
    @Autowired
    public AccountLifecycleService(LifecycleRepository store,SessionAccess access,SessionRepository sessions,
            OrganizationRepository organizations,OrganizationSnapshotStore snapshots,OutboxRepository outbox,
            RetentionPolicy retention,AccountNoticeDelivery delivery,PasswordEncoder passwords,Clock clock,
            MeterRegistry metrics,PlatformTransactionManager manager,com.unidocs.auth.group.personal.PersonalAccountDeparture personalDeparture,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional,
            ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> canaryProvider) {
        this(store,access,sessions,organizations,snapshots,outbox,retention,delivery,passwords,clock,metrics,manager,personalDeparture,
                professional,canaryProvider.getIfAvailable());
    }
    public AccountLifecycleService(LifecycleRepository store,SessionAccess access,SessionRepository sessions,
            OrganizationRepository organizations,OrganizationSnapshotStore snapshots,OutboxRepository outbox,
            RetentionPolicy retention,AccountNoticeDelivery delivery,PasswordEncoder passwords,Clock clock,
            MeterRegistry metrics,PlatformTransactionManager manager,com.unidocs.auth.group.personal.PersonalAccountDeparture personalDeparture,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional) {
        this(store,access,sessions,organizations,snapshots,outbox,retention,delivery,passwords,clock,metrics,manager,personalDeparture,
                professional,(com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary)null);
    }
    private AccountLifecycleService(LifecycleRepository store,SessionAccess access,SessionRepository sessions,
            OrganizationRepository organizations,OrganizationSnapshotStore snapshots,OutboxRepository outbox,
            RetentionPolicy retention,AccountNoticeDelivery delivery,PasswordEncoder passwords,Clock clock,
            MeterRegistry metrics,PlatformTransactionManager manager,com.unidocs.auth.group.personal.PersonalAccountDeparture personalDeparture,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary) {
        this.professional=professional;
        this.canary=canary;
        this.store=store;this.access=access;this.sessions=sessions;this.organizations=organizations;this.snapshots=snapshots;
        this.outbox=outbox;this.retention=retention;this.delivery=delivery;this.passwords=passwords;this.clock=clock;this.metrics=metrics;
        this.personalDeparture=personalDeparture;
        dummyHash=passwords.encode(UUID.randomUUID().toString());
        transactions=new TransactionTemplate(manager);transactions.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        transactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }
    public Options options(UUID sid,UUID subject,UUID after,int limit) {
        pageSize(limit);
        return access.execute(sid,subject,context->{
            List<Account> all=store.options(context.owner().userId(),after,limit+1);
            List<Account> page=List.copyOf(all.subList(0,Math.min(limit,all.size())));
            return new Options(page,store.options(context.owner().userId(),null,2).size()>1,
                    all.size()>limit?page.getLast().id():null);
        });
    }
    public Result remove(UUID sid,UUID subject,LifecycleRequests.Remove request) {
        if(request==null || request.requestId()==null) throw new LifecycleFailure(HttpStatus.BAD_REQUEST,"INVALID_ACCOUNT_ACTION");
        UUID accountId=access.execute(sid,subject,context->select(context,request.accountId()).id());
        Proof proof=store.proof(accountId,false).orElse(null);
        boolean matched=match(request.password(),proof);
        Result result=access.execute(sid,subject,context->{
            Account account=select(context,request.accountId());
            if(!account.id().equals(accountId)) throw LifecycleFailure.conflict("ACCOUNT_SELECTION_CHANGED");
            if(!store.verify(proof,matched,context.now())) {
                sessions.audit(account.userId(),account.id(),sid,"ACCOUNT_RECOVERY_FAILED",context.now());return failed(account.id());
            }
            ensureNotice(account.userId());
            if(account.organizationId()!=null) {
                if(!Set.of("ACTIVE","BLACKLISTED").contains(account.status())) throw LifecycleFailure.conflict("ACCOUNT_NOT_ACTIVE");
                boolean existing=store.removal(request.requestId(),false).isPresent();
                Removal removal=store.request(request.requestId(),account,context.now());
                if(!existing) {
                    sessions.audit(account.userId(),account.id(),sid,"ACCOUNT_REMOVAL_REQUESTED",context.now());
                    outbox.lifecycle("ACCOUNT_REMOVAL_REQUEST",removal.id(),1,"ACCOUNT_REMOVAL_REQUESTED",account.id(),account.organizationId(),null,context.now());
                }
                return new Result(account.id(),removal.status(),null,null,removal.id());
            }
            if(!"ACTIVE".equals(account.status())) throw LifecycleFailure.conflict("ACCOUNT_NOT_ACTIVE");
            changeAccountOrganizations(account,context.now());
            if(store.lastAccountOwner(account.id())) throw LifecycleFailure.conflict("LAST_ORGANIZATION_OWNER");
            personalDeparture.assertDepartureAllowed(account.id(),clock.instant(),true);
            Instant deadline=retention.deadline(context.now());store.personalRemove(account,deadline,context.now());
            reconcile(account.userId(),account.groupId(),context.now());
            UUID notice=changed(account,"ACCOUNT_SOFT_DELETED","Requested by account owner",deadline,sid,context.now());
            return new Result(account.id(),"SOFT_DELETED",deadline,notice,null);
        });
        Result response=checked(result);
        if("SOFT_DELETED".equals(response.status())) invalidateAccountOrganizations(response.accountId());
        return response;
    }
    private Account select(Context context,UUID selected) {
        if(selected==null) {
            List<Account> accounts=store.options(context.owner().userId(),null,2);
            if(accounts.size()!=1) throw LifecycleFailure.conflict("ACCOUNT_SELECTION_REQUIRED");
            selected=accounts.getFirst().id();
        }
        Account account=store.account(selected,true).orElseThrow(LifecycleFailure::forbidden);
        if(!account.userId().equals(context.owner().userId()) || !store.linked(account) || "PURGED".equals(account.status()))
            throw LifecycleFailure.forbidden();
        return account;
    }
    public Result restorePersonal(UUID accountId,LifecycleRequests.Restore request) {
        Account candidate=store.account(accountId,false).orElse(null);
        Proof proof=store.proof(accountId,false).orElse(null);boolean matched=match(request.password(),proof);
        Result result=transactions.execute(tx->{
            if(candidate==null) return failed(accountId);
            sessions.lockGroup(candidate.groupId());
            Account account=store.account(accountId,true).orElseThrow(AuthenticationFailure::new);Instant now=clock.instant();
            if(!store.verify(proof,matched,now)) {
                sessions.audit(account.userId(),account.id(),null,"ACCOUNT_RECOVERY_FAILED",now);return failed(accountId);
            }
            if(!"PERSONAL".equals(account.type()) || !retention.recoverable(account.status(),account.retainUntil(),now)) return failed(accountId);
            ensureNotice(account.userId());store.restorePersonal(account,now);store.fallback(account.userId(),now);
            changeAccountOrganizations(account,now);
            UUID notice=changed(account,"ACCOUNT_RESTORED","Restored by account owner",null,null,now);
            return new Result(accountId,"ACTIVE",null,notice,null);
        });
        Result response=checked(result);invalidateAccountOrganizations(accountId);return response;
    }
    public Result adminAction(UUID sid,UUID subject,UUID org,UUID membership,LifecycleRequests.AdminAction request) {
        if(request==null || request.adminAccountId()==null || request.action()==null) throw new LifecycleFailure(HttpStatus.BAD_REQUEST,"INVALID_ACCOUNT_ACTION");
        reason(request.reason());
        Member target=store.member(org,membership).orElseThrow(LifecycleFailure::forbidden);
        Proof proof=store.proof(request.adminAccountId(),false).orElse(null);boolean matched=match(request.password(),proof);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=
                checkCanary(sid,subject,org,request.adminAccountId());
        AdminResult result=access.executeForGroups(sid,subject,List.of(target.groupId()),context->{
            store.lockOrganization(org);
            Role role=admin(context,org,request.adminAccountId(),decision);
            if(decision!=null)canary.revalidate(decision,context,request.adminAccountId(),org);
            Member current=store.member(org,membership).orElseThrow(LifecycleFailure::forbidden);
            if(!current.userId().equals(target.userId())) throw LifecycleFailure.forbidden();
            if(!store.verify(proof,matched,context.now())) return new AdminResult(failed(current.accountId()),0);
            Result response=mutate(context,org,current,role,request.adminAccountId(),request.action(),request.blacklistUntil(),request.reason());
            return new AdminResult(response,store.bumpOrganization(org,context.now()));
        });
        Result response=checked(result.result());snapshots.invalidate(org,result.version());return response;
    }
    private Result mutate(Context context,UUID org,Member target,Role actorRole,UUID actorAccount,
            LifecycleRequests.Action action,Instant blockedUntil,String reason) {
        if(target.userId().equals(context.owner().userId())) throw LifecycleFailure.forbidden();
        if(store.ownsOrganization(target.userId(),org) && actorRole!=Role.OWNER) throw LifecycleFailure.forbidden();
        ensureNotice(target.userId());
        Account account=store.account(target.accountId(),true).orElseThrow(LifecycleFailure::forbidden);
        // Memberships may attach to Personal roots; the notice still names the selected organization.
        Account noticeAccount=new Account(account.id(),account.userId(),account.groupId(),org,account.type(),account.displayName(),account.status(),account.version(),account.retainUntil());
        Restriction restriction=store.restriction(org,target.userId(),true).orElse(null);
        String event;Instant deadline=null;
        if(action==LifecycleRequests.Action.RESTORE) {
            if(restriction==null || !Set.of("REMOVED","BLACKLISTED").contains(restriction.status())) throw LifecycleFailure.conflict("MEMBER_NOT_REMOVED");
            if("REMOVED".equals(restriction.status()) && !context.now().isBefore(restriction.retainUntil())) throw LifecycleFailure.conflict("RETENTION_EXPIRED");
            store.restoreRestriction(restriction,context.now());event="ORGANIZATION_MEMBER_RESTORED";
        } else {
            if(store.lastOwner(target.userId(),org)) throw LifecycleFailure.conflict("LAST_ORGANIZATION_OWNER");
            if(restriction!=null && Set.of("REMOVED","PURGED").contains(restriction.status())) throw LifecycleFailure.conflict("MEMBER_ALREADY_REMOVED");
            if(action==LifecycleRequests.Action.BLACKLIST) {
                if(blockedUntil==null || !blockedUntil.isAfter(context.now()) || blockedUntil.isAfter(context.now().plusSeconds(365L*86400)))
                    throw LifecycleFailure.conflict("INVALID_BLACKLIST_EXPIRY");
                deadline=blockedUntil;event="ORGANIZATION_MEMBER_BLACKLISTED";
            } else { deadline=retention.deadline(context.now());event="ORGANIZATION_MEMBER_REMOVED"; }
            store.restrict(org,target,actorAccount,action==LifecycleRequests.Action.REMOVE?"REMOVED":"BLACKLISTED",deadline,context.now());
        }
        reconcile(target.userId(),target.groupId(),context.now());
        UUID notice=store.notice(noticeAccount,event,reason,deadline,context.now());
        sessions.audit(target.userId(),target.accountId(),context.session().id(),event,context.now());
        long version=organizations.visibility(actorAccount,"PASSWORD",org).orElseThrow(LifecycleFailure::forbidden).authorizationVersion()+1;
        Restriction current=store.restriction(org,target.userId(),true).orElseThrow();
        outbox.lifecycleSubject("ORGANIZATION",org,version,event,target.accountId(),org,target.userId(),current.id(),deadline,context.now());
        outbox.lifecycle("SECURITY_NOTICE",notice,1,"SECURITY_NOTICE_CREATED",target.accountId(),org,deadline,context.now());
        return new Result(target.accountId(),action==LifecycleRequests.Action.RESTORE?"ACTIVE":action==LifecycleRequests.Action.REMOVE?"REMOVED":"BLACKLISTED",deadline,notice,null);
    }
    public Result review(UUID sid,UUID subject,UUID org,UUID requestId,LifecycleRequests.Review request) {
        if(request==null || request.adminAccountId()==null) throw new LifecycleFailure(HttpStatus.BAD_REQUEST,"INVALID_ACCOUNT_ACTION");
        reason(request.reason());
        Removal candidate=store.removal(requestId,false).orElseThrow(LifecycleFailure::forbidden);
        Account target=store.account(candidate.accountId(),false).orElseThrow(LifecycleFailure::forbidden);
        Proof proof=store.proof(request.adminAccountId(),false).orElse(null);boolean matched=match(request.password(),proof);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=
                checkCanary(sid,subject,org,request.adminAccountId());
        AdminResult result=access.executeForGroups(sid,subject,List.of(target.groupId()),context->{
            store.lockOrganization(org);Role role=admin(context,org,request.adminAccountId(),decision);
            if(decision!=null)canary.revalidate(decision,context,request.adminAccountId(),org);
            Removal removal=store.removal(requestId,true).orElseThrow(LifecycleFailure::forbidden);
            if(!removal.organizationId().equals(org) || removal.userId().equals(context.owner().userId())) throw LifecycleFailure.forbidden();
            if(!"PENDING".equals(removal.status())) throw LifecycleFailure.conflict("REMOVAL_ALREADY_REVIEWED");
            if(!store.verify(proof,matched,context.now())) return new AdminResult(failed(removal.accountId()),0);
            Result response;long version=0;
            if(request.approve()) {
                Member member=store.memberForAccount(org,target.id()).orElseThrow(LifecycleFailure::forbidden);
                response=mutate(context,org,member,role,request.adminAccountId(),LifecycleRequests.Action.REMOVE,null,request.reason());
                version=store.bumpOrganization(org,context.now());
            } else {
                ensureNotice(target.userId());UUID notice=store.notice(target,"ACCOUNT_REMOVAL_REJECTED",request.reason(),null,context.now());
                sessions.audit(target.userId(),target.id(),sid,"ACCOUNT_REMOVAL_REJECTED",context.now());
                outbox.lifecycle("SECURITY_NOTICE",notice,1,"SECURITY_NOTICE_CREATED",target.id(),org,null,context.now());
                response=new Result(target.id(),"REJECTED",null,notice,requestId);
            }
            store.review(removal,request.adminAccountId(),request.approve()?"APPROVED":"REJECTED",context.now());
            outbox.lifecycle("ACCOUNT_REMOVAL_REQUEST",removal.id(),2,"ACCOUNT_REMOVAL_REQUEST_REVIEWED",target.id(),org,response.retainUntil(),context.now());
            return new AdminResult(response,version);
        });
        Result response=checked(result.result());if(result.version()>0) snapshots.invalidate(org,result.version());return response;
    }
    public Page<Removal> removals(UUID sid,UUID subject,UUID org,UUID adminAccount,UUID after,int limit) {
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision=org==null?null:
                checkCanary(sid,subject,org,adminAccount);
        pageSize(limit);return access.execute(sid,subject,context->{
            if(org!=null) admin(context,org,adminAccount,decision);
            if(decision!=null)canary.revalidate(decision,context,adminAccount,org);
            List<Removal> all=store.removals(org,context.owner().userId(),after,limit+1);
            List<Removal> page=List.copyOf(all.subList(0,Math.min(limit,all.size())));
            return new Page<>(page,all.size()>limit?page.getLast().id():null);
        });
    }
    public Page<Notice> notices(UUID sid,UUID subject,UUID after,int limit) {
        pageSize(limit);return access.execute(sid,subject,context->{
            List<Notice> all=store.notices(context.owner().userId(),after,limit+1);
            List<Notice> page=List.copyOf(all.subList(0,Math.min(limit,all.size())));
            return new Page<>(page,all.size()>limit?page.getLast().id():null);
        });
    }
    private Role admin(Context context,UUID org,UUID account,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision) {
        if(organizations.university(org)) throw LifecycleFailure.forbidden();
        SessionAccountGrant grant=sessions.liveGrant(context.session(),account,context.now()).orElseThrow(LifecycleFailure::forbidden);
        if(!Set.of("LOGIN","PASSWORD").contains(grant.authMethod())) throw LifecycleFailure.forbidden();
        Role role=organizations.visibility(account,grant.authMethod(),org).orElseThrow(LifecycleFailure::forbidden).role();
        if(professional.professional(org)) {
            if(canary!=null)canary.requireDecision(org,null,"organization.employee.remove",decision);
            if(decision==null || !decision.enforcing())
                professional.require(context,account,org,null,"auth-service","organization.employee.remove");
            return role;
        }
        if(role==Role.MEMBER) throw LifecycleFailure.forbidden();return role;
    }
    private com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision checkCanary(
            UUID sid,UUID subject,UUID org,UUID account) {
        return canary!=null && canary.applies(org,"organization.employee.remove")
                ? canary.check(sid,subject,account,org,"organization.employee.remove"):null;
    }
    private UUID changed(Account account,String event,String reason,Instant deadline,UUID sid,Instant now) {
        UUID notice=store.notice(account,event,reason,deadline,now);
        sessions.audit(account.userId(),account.id(),sid,event,now);
        outbox.lifecycle("USER_ACCOUNT",account.id(),account.version()+1,event,account.id(),account.organizationId(),deadline,now);
        outbox.lifecycle("SECURITY_NOTICE",notice,1,"SECURITY_NOTICE_CREATED",account.id(),account.organizationId(),deadline,now);
        metrics.counter("account.lifecycle","action",event).increment();return notice;
    }
    private void ensureNotice(UUID user) {
        if(store.employee(user) && store.email(user).isEmpty()) return; // Durable authenticated inbox is the employee notice channel.
        if(!delivery.enabled() || store.email(user).isEmpty()) throw new LifecycleFailure(HttpStatus.SERVICE_UNAVAILABLE,"SECURITY_NOTICE_DELIVERY_UNAVAILABLE");
    }
    private boolean match(String password,Proof proof) {
        if(password==null || password.isBlank() || password.length()>128) throw new AuthenticationFailure();
        return passwords.matches(password,proof==null?dummyHash:proof.hash());
    }
    private static Result failed(UUID account) { return new Result(account,"AUTHENTICATION_FAILED",null,null,null); }
    private static Result checked(Result result) {
        if(result==null || "AUTHENTICATION_FAILED".equals(result.status())) throw new AuthenticationFailure();return result;
    }
    private record AdminResult(Result result,long version) { }
    private void changeAccountOrganizations(Account account,Instant now) {
        UUID after=null;
        while(true) {
            List<OrganizationVersion> page=store.accountOrganizations(account.id(),after,100);if(page.isEmpty()) break;
            for(OrganizationVersion org:page) {
                store.lockOrganization(org.id());long version=store.bumpOrganization(org.id(),now);
                outbox.lifecycle("ORGANIZATION",org.id(),version,"ORGANIZATION_ACCOUNT_AVAILABILITY_CHANGED",account.id(),org.id(),null,now);
            }
            after=page.getLast().id();
        }
    }
    private void invalidateAccountOrganizations(UUID account) {
        UUID after=null;
        while(true) {
            List<OrganizationVersion> page=store.accountOrganizations(account,after,100);if(page.isEmpty()) break;
            for(OrganizationVersion org:page) snapshots.invalidate(org.id(),org.version());
            after=page.getLast().id();
        }
    }
    private static void pageSize(int limit) { if(limit<1 || limit>100) throw LifecycleFailure.conflict("INVALID_PAGE_SIZE"); }
    private static void reason(String reason) {
        if(reason==null || reason.isBlank() || reason.length()>500) throw new LifecycleFailure(HttpStatus.BAD_REQUEST,"INVALID_NOTICE_REASON");
    }
    void reconcile(UUID user,UUID group,Instant now) {
        store.fallback(user,now);
        sessions.reconcileGroup(group,now);
    }
    public void maintain() {
        Instant now=clock.instant();
        for(Account candidate:store.duePersonal(now,20)) transactions.executeWithoutResult(tx->{
            sessions.lockGroup(candidate.groupId());Account account=store.account(candidate.id(),true).orElseThrow();Instant current=clock.instant();
            if(!"SOFT_DELETED".equals(account.status()) || account.retainUntil()==null || current.isBefore(account.retainUntil())) return;
            store.purge(account,current);reconcile(account.userId(),account.groupId(),current);
            sessions.audit(account.userId(),account.id(),null,"ACCOUNT_PURGED",current);
            outbox.lifecycle("USER_ACCOUNT",account.id(),account.version()+1,"ACCOUNT_PURGED",account.id(),null,null,current);
        });
        for(Restriction candidate:store.dueRestrictions(now,20)) {
            Long version=transactions.execute(tx->{
                sessions.lockGroup(candidate.groupId());store.lockOrganization(candidate.organizationId());
                Restriction restriction=store.restriction(candidate.organizationId(),candidate.userId(),true).orElseThrow();Instant current=clock.instant();
                Account account=store.restrictedAccount(restriction).orElse(null);
                if("BLACKLISTED".equals(restriction.status()) && !current.isBefore(restriction.blacklistUntil())) {
                    store.restoreRestriction(restriction,current);
                    if(account!=null) {
                        Account noticeAccount=new Account(account.id(),account.userId(),account.groupId(),restriction.organizationId(),account.type(),account.displayName(),account.status(),account.version(),account.retainUntil());
                        UUID notice=store.notice(noticeAccount,"ORGANIZATION_MEMBER_RESTORED","Temporary blacklist expired",null,current);
                        outbox.lifecycle("SECURITY_NOTICE",notice,1,"SECURITY_NOTICE_CREATED",account.id(),restriction.organizationId(),null,current);
                        sessions.audit(account.userId(),account.id(),null,"ORGANIZATION_MEMBER_RESTORED",current);
                    }
                } else if("REMOVED".equals(restriction.status()) && !current.isBefore(restriction.retainUntil())) {
                    store.purgeRestriction(restriction,current);
                    if(account!=null) sessions.audit(account.userId(),account.id(),null,"ACCOUNT_PURGED",current);
                } else return null;
                reconcile(restriction.userId(),restriction.groupId(),current);long next=store.bumpOrganization(restriction.organizationId(),current);
                String event="BLACKLISTED".equals(restriction.status())?"ORGANIZATION_MEMBER_RESTORED":"ORGANIZATION_ACCOUNT_PURGED";
                outbox.lifecycleSubject("ORGANIZATION",restriction.organizationId(),next,event,account==null?null:account.id(),restriction.organizationId(),restriction.userId(),restriction.id(),null,current);
                return next;
            });
            if(version!=null) snapshots.invalidate(candidate.organizationId(),version);
        }
    }
}
