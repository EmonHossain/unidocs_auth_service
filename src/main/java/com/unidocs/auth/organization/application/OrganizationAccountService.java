package com.unidocs.auth.organization.application;

import java.util.*;

import jakarta.validation.Validator;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.*;

import io.micrometer.core.instrument.MeterRegistry;

import com.unidocs.auth.organization.api.*;
import com.unidocs.auth.organization.api.OrganizationAccountResponse;
import com.unidocs.auth.organization.domain.OrganizationInvitation;
import com.unidocs.auth.organization.persistence.*;
import com.unidocs.auth.organization.persistence.OrganizationAccountRepository.Provisioned;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;

@Service
@Transactional(propagation=Propagation.NEVER)
public class OrganizationAccountService {
    private final OrganizationAccountRepository accounts;
    private final InvitationRepository invitations;
    private final OrganizationRepository organizations;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final InvitationTokens tokens;
    private final PasswordEncoder passwords;
    private final OutboxRepository outbox;
    private final Validator validator;
    private final MeterRegistry metrics;
    public OrganizationAccountService(OrganizationAccountRepository accounts,InvitationRepository invitations,
            OrganizationRepository organizations,SessionAccess access,SessionRepository sessions,InvitationTokens tokens,
            PasswordEncoder passwords,OutboxRepository outbox,Validator validator,MeterRegistry metrics) {
        this.accounts=accounts; this.invitations=invitations; this.organizations=organizations; this.access=access;
        this.sessions=sessions; this.tokens=tokens; this.passwords=passwords; this.outbox=outbox; this.validator=validator; this.metrics=metrics;
    }
    public OrganizationAccountResponse provision(UUID sid,UUID subject,UUID organization,UUID invitation,OrganizationAccountRequest request) {
        if(organizations.university(organization)) throw denied();
        if(request==null || !validator.validate(request).isEmpty()) throw new OrganizationFailure(HttpStatus.BAD_REQUEST);
        Provisioned before=accounts.provisioned(invitation).orElse(null);
        // Password hashing/checks remain outside transactions, including concurrent idempotent retries.
        String newHash=before==null?passwords.encode(request.password()):null;
        boolean matched=before!=null && passwords.matches(request.password(),before.passwordHash());
        Result result=execute(sid,subject,organization,invitation,request,before,matched,newHash);
        if(result.recheck()!=null) {
            Provisioned snapshot=result.recheck();
            matched=passwords.matches(request.password(),snapshot.passwordHash());
            result=execute(sid,subject,organization,invitation,request,snapshot,matched,null);
            if(result.recheck()!=null) throw new OrganizationFailure(HttpStatus.CONFLICT);
        }
        metrics.counter("organization.account.provision","outcome",result.outcome()).increment();
        if(result.response()==null) throw denied();
        return result.response();
    }
    private Result execute(UUID sid,UUID subject,UUID organization,UUID invitationId,OrganizationAccountRequest request,
            Provisioned before,boolean passwordMatched,String newHash) {
        return access.execute(sid,subject,actor->{
            SessionAccountGrant grant=sessions.liveGrant(actor.session(),request.accountId(),actor.now()).orElseThrow(OrganizationAccountService::denied);
            if(!Set.of("LOGIN","PASSWORD").contains(grant.authMethod())) throw denied();
            String primary=organizations.verifiedEmail(actor.owner().userId()).orElseThrow(OrganizationAccountService::denied);
            if(!invitations.lockUsableOrganization(organization)) throw denied();
            if(accounts.type(organization)!=com.unidocs.auth.organization.domain.Organization.Type.UNIVERSITY) throw denied();
            if(!invitations.userCanJoin(organization,actor.owner().userId())) throw denied();
            OrganizationInvitation invitation=invitations.lock(invitationId).orElseThrow(OrganizationAccountService::denied);
            if(!invitation.organizationId().equals(organization)) throw denied();
            boolean proof=tokens.matches(request.token(),invitation.tokenHash());
            if(invitation.status()==OrganizationInvitation.Status.ACCEPTED) {
                if(!request.accountId().equals(invitation.provisioningAccountId()) || !proof) throw denied();
                Provisioned current=accounts.provisioned(invitationId).orElseThrow(OrganizationAccountService::denied);
                if(!current.userId().equals(actor.owner().userId()) || !current.groupId().equals(actor.session().accountGroupId())
                        || !current.available() || !current.response().organizationId().equals(organization)
                        || !current.response().accountId().equals(invitation.acceptedAccountId())) throw denied();
                if(before==null || !current.identityId().equals(before.identityId()) || current.credentialVersion()!=before.credentialVersion()
                        || !current.passwordHash().equals(before.passwordHash())) return new Result(null,"recheck",current);
                if(!passwordMatched || !current.response().displayName().equals(request.displayName().strip())) throw new OrganizationFailure(HttpStatus.CONFLICT);
                sessions.touch(actor.session(),grant,actor.now());
                return new Result(current.response(),"retried",null);
            }
            if(!invitations.issuerCurrent(invitation)) throw denied();
            // A different verified Personal address cannot exhaust someone else's invitation proof.
            if(!proof && !primary.equals(invitation.officialEmail())) throw denied();
            long previous=invitation.version();
            if(!invitation.verifyProof(proof,actor.now())) {
                if(invitation.version()!=previous) {
                    sessions.audit(actor.owner().userId(),request.accountId(),sid,"ORGANIZATION_INVITATION_FAILED",actor.now());
                    outbox.invitationChanged(invitation.id(),organization,invitation.version(),invitation.status().name(),actor.now());
                    invitations.flush();
                }
                return new Result(null,"failed",null);
            }
            if(accounts.hasHumanMembership(organization,actor.owner().userId())) throw new OrganizationFailure(HttpStatus.CONFLICT);
            OrganizationAccountResponse response=accounts.create(actor,request.accountId(),organization,request.displayName().strip(),Objects.requireNonNull(newHash),invitation.officialEmail());
            invitation.acceptProvisioned(request.accountId(),response.accountId(),response.membershipId(),actor.now());
            invitations.flush();
            for(String event:List.of("ORGANIZATION_ACCOUNT_PROVISIONED","ACCOUNT_LINKED","ORGANIZATION_MEMBERSHIP_ACTIVATED"))
                sessions.audit(actor.owner().userId(),response.accountId(),sid,event,actor.now());
            outbox.invitationChanged(invitation.id(),organization,invitation.version(),invitation.status().name(),actor.now());
            outbox.accountProvisioned(response.accountId(),organization,response.membershipId(),actor.now());
            outbox.membershipActivated(organization,response.membershipId(),response.accountId(),invitation.id(),accounts.authorizationVersion(organization),actor.now());
            sessions.touch(actor.session(),grant,actor.now());
            return new Result(response,"succeeded",null);
        });
    }
    private record Result(OrganizationAccountResponse response,String outcome,Provisioned recheck) { }
    private static OrganizationFailure denied() { return new OrganizationFailure(HttpStatus.FORBIDDEN); }
}
