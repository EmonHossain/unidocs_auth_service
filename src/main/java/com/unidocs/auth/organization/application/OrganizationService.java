package com.unidocs.auth.organization.application;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.List;
import java.util.Optional;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.*;

import com.unidocs.auth.organization.api.*;
import com.unidocs.auth.organization.api.OrganizationResponse;
import com.unidocs.auth.organization.domain.*;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.OrganizationRepository.Creation;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;

@Service
@Transactional(propagation=Propagation.NEVER)
public class OrganizationService {
    private final OrganizationRepository organizations;
    private final OutboxRepository outbox;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final io.micrometer.core.instrument.MeterRegistry metrics;
    private final com.unidocs.auth.authorization.application.OrganizationSnapshotStore snapshots;
    public OrganizationService(OrganizationRepository organizations, OutboxRepository outbox, SessionAccess access, SessionRepository sessions,
            io.micrometer.core.instrument.MeterRegistry metrics,
            com.unidocs.auth.authorization.application.OrganizationSnapshotStore snapshots) {
        this.organizations=organizations; this.outbox=outbox; this.access=access; this.sessions=sessions;
        this.metrics=metrics;
        this.snapshots=snapshots;
    }
    public OrganizationResponse create(UUID sid, UUID subject, OrganizationRequest request) {
        try {
            OrganizationResponse result = access.execute(sid,subject,context->{
                SessionAccountGrant grant=grant(context,request.accountId());
                if(!Set.of("LOGIN","PASSWORD").contains(grant.authMethod())) throw denied();
                String fingerprint=fingerprint(request);
                Optional<Creation> existing=organizations.creation(request.accountId(),request.requestId());
                if(existing.isPresent()) {
                    if(!existing.get().fingerprint().equals(fingerprint)) throw new OrganizationFailure(HttpStatus.CONFLICT);
                    return read(context,grant,existing.get().id());
                }
                String email=organizations.verifiedEmail(context.owner().userId()).orElseThrow(OrganizationService::denied);
                Organization organization=new Organization(UUID.randomUUID(),request.name(),request.slug(),request.type(),request.accountId(),request.requestId(),fingerprint,context.now());
                OrganizationMembership membership=new OrganizationMembership(UUID.randomUUID(),organization.id(),request.accountId(),email,context.now());
                organizations.create(organization,new OrganizationAuthPolicy(UUID.randomUUID(),organization.id(),context.now()),membership);
                sessions.audit(context.owner().userId(),request.accountId(),sid,"ORGANIZATION_CREATED",context.now());
                sessions.audit(context.owner().userId(),request.accountId(),sid,"ORGANIZATION_MEMBERSHIP_ACTIVATED",context.now());
                outbox.organizationCreated(organization.id(),membership.id(),request.accountId(),context.now());
                return read(context,grant,organization.id());
            });
            com.unidocs.auth.shared.config.TrustedRequestContext.authorizedOrganization(result.id());
            metrics.counter("organization.bootstrap", "outcome", "succeeded").increment();
            return result;
        } catch(DataIntegrityViolationException conflict) {
            metrics.counter("organization.bootstrap", "outcome", "conflict").increment();
            throw new OrganizationFailure(HttpStatus.CONFLICT);
        } catch(OrganizationFailure failure) {
            metrics.counter("organization.bootstrap", "outcome", "denied").increment();
            throw failure;
        }
    }
    public OrganizationResponse get(UUID sid, UUID subject, UUID account, UUID organization) {
        if (!snapshots.enabled()) {
            OrganizationResponse result = access.execute(sid,subject,c->read(c,grant(c,account),organization));
            com.unidocs.auth.shared.config.TrustedRequestContext.authorizedOrganization(result.id());
            return result;
        }
        Optional<OrganizationResponse> cached = snapshots.find(account,organization);
        OrganizationResponse result = access.execute(sid,subject,c->{
            SessionAccountGrant grant=grant(c,account);
            OrganizationRepository.Visibility current = organizations.visibility(account,grant.authMethod(),organization)
                    .orElseThrow(OrganizationService::denied);
            if (cached.isPresent() && current.matches(cached.get(),account,organization)) {
                sessions.touch(c.session(),grant,c.now());
                return cached.get();
            }
            return read(c,grant,organization);
        });
        com.unidocs.auth.shared.config.TrustedRequestContext.authorizedOrganization(result.id());
        if (cached.isEmpty() || !cached.get().equals(result)) snapshots.put(result);
        // Session/organization transactions have committed before Redis I/O.
        return result;
    }
    public record Page(List<OrganizationResponse> organizations, UUID nextCursor) { }
    public Page list(UUID sid, UUID subject, UUID account, UUID after, int limit) {
        if(limit<1 || limit>100) throw new OrganizationFailure(HttpStatus.BAD_REQUEST);
        return access.execute(sid,subject,c->{
            SessionAccountGrant grant=grant(c,account);
            List<OrganizationResponse> rows=organizations.visible(account,grant.authMethod(),null,after,limit+1);
            boolean more=rows.size()>limit;
            List<OrganizationResponse> page=List.copyOf(rows.subList(0,Math.min(limit,rows.size())));
            sessions.touch(c.session(),grant,c.now());
            return new Page(page,more?page.getLast().id():null);
        });
    }
    private OrganizationResponse read(SessionAccess.Context context, SessionAccountGrant grant, UUID id) {
        OrganizationResponse result=organizations.visible(grant.accountId(),grant.authMethod(),id,null,1).stream().findFirst().orElseThrow(OrganizationService::denied);
        sessions.touch(context.session(),grant,context.now());
        return result;
    }
    private SessionAccountGrant grant(SessionAccess.Context c, UUID account) {
        return sessions.liveGrant(c.session(),Objects.requireNonNull(account),c.now()).orElseThrow(OrganizationService::denied);
    }
    private static OrganizationFailure denied() { return new OrganizationFailure(HttpStatus.FORBIDDEN); }
    private static String fingerprint(OrganizationRequest request) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                (request.name().strip()+"\n"+request.slug()+"\n"+request.type().name()).getBytes(StandardCharsets.UTF_8))); }
        catch(java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
