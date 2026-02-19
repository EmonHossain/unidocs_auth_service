package com.unidocs.auth.organization.application;

import java.time.Instant;
import java.util.*;

import jakarta.validation.Validator;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.*;

import io.micrometer.core.instrument.MeterRegistry;

import com.unidocs.auth.organization.api.*;
import com.unidocs.auth.organization.api.OrganizationResponse;
import com.unidocs.auth.organization.application.InvitationDelivery;
import com.unidocs.auth.organization.domain.*;
import com.unidocs.auth.organization.domain.OrganizationInvitation;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.*;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;

@Service
@Transactional(propagation=Propagation.NEVER)
public class InvitationService {
    private final InvitationRepository invitations;
    private final OrganizationRepository organizations;
    private final SessionRepository sessions;
    private final SessionAccess access;
    private final InvitationTokens tokens;
    private final ObjectProvider<InvitationDelivery> delivery;
    private final OutboxRepository outbox;
    private final Validator validator;
    private final MeterRegistry metrics;
    public InvitationService(InvitationRepository invitations, OrganizationRepository organizations, SessionRepository sessions,
            SessionAccess access, InvitationTokens tokens, ObjectProvider<InvitationDelivery> delivery,
            OutboxRepository outbox, Validator validator, MeterRegistry metrics) {
        this.invitations=invitations; this.organizations=organizations; this.sessions=sessions;
        this.access=access; this.tokens=tokens; this.delivery=delivery; this.outbox=outbox; this.validator=validator; this.metrics=metrics;
    }
    public InvitationResponse issue(UUID sid, UUID subject, UUID organization, InvitationRequest request) {
        validate(request);
        String email=request.email().strip().toLowerCase(Locale.ROOT);
        String proof=tokens.generate();
        Issued result=access.execute(sid,subject,context->{
            SessionAccountGrant grant=passwordGrant(context,request.accountId());
            if(!invitations.lockUsableOrganization(organization)) throw denied();
            OrganizationResponse issuer=organizations.visible(request.accountId(),grant.authMethod(),organization,null,1).stream().findFirst().orElseThrow(InvitationService::denied);
            // Institutional admission is verification-based; legacy administrative invitations are closed.
            requireLegacyInvitationSupport();
            if(issuer.role()!=OrganizationMembership.Role.OWNER && issuer.role()!=OrganizationMembership.Role.ADMIN) throw denied();
            InvitationDelivery provider=delivery.getIfAvailable();
            if(provider==null) throw new OrganizationFailure(HttpStatus.SERVICE_UNAVAILABLE);
            for(OrganizationInvitation previous:invitations.pending(organization,email)) {
                previous.supersede(context.now());
                audit(context,request.accountId(),"ORGANIZATION_INVITATION_SUPERSEDED");
                outbox.invitationChanged(previous.id(),organization,previous.version(),previous.status().name(),context.now());
            }
            invitations.flush();
            OrganizationInvitation invitation=new OrganizationInvitation(UUID.randomUUID(),organization,request.accountId(),issuer.membershipId(),
                    issuer.membershipVersion(),email,tokens.hash(proof),context.now());
            invitations.save(invitation);
            audit(context,request.accountId(),"ORGANIZATION_INVITATION_CREATED");
            outbox.invitationChanged(invitation.id(),organization,invitation.version(),invitation.status().name(),context.now());
            sessions.touch(context.session(),grant,context.now());
            return new Issued(new InvitationResponse(invitation.id(),organization,invitation.status(),invitation.expiresAt()),provider);
        });
        try {
            result.provider().deliver(email,organization,result.response().id(),proof,result.response().expiresAt());
        } catch(RuntimeException failure) {
            metrics.counter("organization.invitation.delivery","outcome","failed").increment();
            throw new OrganizationFailure(HttpStatus.SERVICE_UNAVAILABLE);
        }
        metrics.counter("organization.invitation.issue","outcome","succeeded").increment();
        return result.response();
    }
    public OrganizationResponse accept(UUID sid, UUID subject, UUID organization, UUID invitationId, InvitationAcceptanceRequest request) {
        requireLegacyInvitationSupport();
        validate(request);
        if(!organizations.university(organization)) throw denied();
        Acceptance result=access.execute(sid,subject,context->{
            SessionAccountGrant grant=passwordGrant(context,request.accountId());
            if(!invitations.lockUsableOrganization(organization)) throw denied();
            if(!invitations.userCanJoin(organization,context.owner().userId())) throw denied();
            OrganizationInvitation invitation=invitations.lock(invitationId).orElseThrow(InvitationService::denied);
            if(!invitation.organizationId().equals(organization)) throw denied();
            String email=organizations.verifiedEmail(context.owner().userId()).orElseThrow(InvitationService::denied);
            if(!invitation.officialEmail().equals(email) || !invitations.accountEmail(request.accountId(),email)) throw denied();
            boolean matches=tokens.matches(request.token(),invitation.tokenHash());
            if(invitation.status()==OrganizationInvitation.Status.ACCEPTED) {
                if(invitation.provisioningAccountId()!=null) throw denied();
                if(!request.accountId().equals(invitation.acceptedAccountId()) || !matches) throw denied();
                OrganizationResponse member=visible(context,grant,organization);
                if(!member.membershipId().equals(invitation.membershipId())) throw denied();
                return new Acceptance(member,"retried");
            }
            if(!invitations.issuerCurrent(invitation)) throw denied();
            long before=invitation.version();
            if(!invitation.verifyProof(matches,context.now())) {
                if(invitation.version()!=before) {
                    audit(context,request.accountId(),"ORGANIZATION_INVITATION_FAILED");
                    outbox.invitationChanged(invitation.id(),organization,invitation.version(),invitation.status().name(),context.now());
                    invitations.flush();
                }
                return new Acceptance(null,"failed");
            }
            // Never resurrect an existing REVOKED membership or replace another invitation's activation.
            if(invitations.hasMembership(organization,request.accountId())) throw new OrganizationFailure(HttpStatus.CONFLICT);
            OrganizationMembership membership=new OrganizationMembership(UUID.randomUUID(),organization,request.accountId(),email,OrganizationMembership.Role.MEMBER,context.now());
            invitations.activate(membership,organization,context.now());
            invitation.accept(request.accountId(),membership.id(),context.now());
            invitations.flush();
            OrganizationResponse member=visible(context,grant,organization);
            audit(context,request.accountId(),"ORGANIZATION_MEMBERSHIP_ACTIVATED");
            outbox.invitationChanged(invitation.id(),organization,invitation.version(),invitation.status().name(),context.now());
            outbox.membershipActivated(organization,membership.id(),request.accountId(),invitation.id(),member.authorizationVersion(),context.now());
            return new Acceptance(member,"succeeded");
        });
        metrics.counter("organization.invitation.accept","outcome",result.outcome()).increment();
        if(result.response()==null) throw denied();
        return result.response();
    }
    private OrganizationResponse visible(SessionAccess.Context context, SessionAccountGrant grant, UUID organization) {
        OrganizationResponse member=organizations.visible(grant.accountId(),grant.authMethod(),organization,null,1).stream().findFirst().orElseThrow(InvitationService::denied);
        sessions.touch(context.session(),grant,context.now()); return member;
    }
    private SessionAccountGrant passwordGrant(SessionAccess.Context context, UUID account) {
        SessionAccountGrant grant=sessions.liveGrant(context.session(),account,context.now()).orElseThrow(InvitationService::denied);
        if(!Set.of("LOGIN","PASSWORD").contains(grant.authMethod())) throw denied();
        return grant;
    }
    private void audit(SessionAccess.Context context, UUID account, String event) {
        sessions.audit(context.owner().userId(),account,context.session().id(),event,context.now());
    }
    private void validate(Object request) {
        if(request==null || !validator.validate(request).isEmpty()) throw new OrganizationFailure(HttpStatus.BAD_REQUEST);
    }
    private static void requireLegacyInvitationSupport() { throw denied(); }
    private static OrganizationFailure denied() { return new OrganizationFailure(HttpStatus.FORBIDDEN); }
    private record Issued(InvitationResponse response, InvitationDelivery provider) { }
    private record Acceptance(OrganizationResponse response, String outcome) { }
}
