package com.unidocs.auth.group.application;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import jakarta.validation.Validator;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.unidocs.auth.group.api.GroupRequest;
import com.unidocs.auth.group.api.GroupResponse;
import com.unidocs.auth.group.domain.Group;
import com.unidocs.auth.group.persistence.GroupRepository;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;

@Service
@Transactional(propagation = Propagation.NEVER)
public class GroupService {
    private final GroupRepository groups;
    private final OrganizationRepository organizations;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final OutboxRepository outbox;
    private final Validator validator;
    private final MeterRegistry metrics;
    private final com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional;
    private final com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary;

    @Autowired
    public GroupService(GroupRepository groups, OrganizationRepository organizations, SessionAccess access,
            SessionRepository sessions, OutboxRepository outbox, Validator validator, MeterRegistry metrics,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional,
            ObjectProvider<com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary> canaryProvider) {
        this(groups, organizations, access, sessions, outbox, validator, metrics, professional, canaryProvider.getIfAvailable());
    }

    public GroupService(GroupRepository groups, OrganizationRepository organizations, SessionAccess access,
            SessionRepository sessions, OutboxRepository outbox, Validator validator, MeterRegistry metrics,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional) {
        this(groups, organizations, access, sessions, outbox, validator, metrics, professional,
                (com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary) null);
    }

    private GroupService(GroupRepository groups, OrganizationRepository organizations, SessionAccess access,
            SessionRepository sessions, OutboxRepository outbox, Validator validator, MeterRegistry metrics,
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService professional,
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary canary) {
        this.professional=professional;
        this.canary=canary;
        this.groups = groups;
        this.organizations = organizations;
        this.access = access;
        this.sessions = sessions;
        this.outbox = outbox;
        this.validator = validator;
        this.metrics = metrics;
    }

    public GroupResponse create(UUID sid, UUID subject, UUID organization, GroupRequest request) {
        if (request == null || !validator.validate(request).isEmpty()) throw new GroupFailure(HttpStatus.BAD_REQUEST);
        String name;
        try { name = Group.normalizedName(request.name()); }
        catch (IllegalArgumentException invalid) { throw new GroupFailure(HttpStatus.BAD_REQUEST); }
        String fingerprint = fingerprint(name, request);
        try {
            com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision =
                    canary != null && canary.applies(organization)
                            ? canary.check(sid, subject, request.accountId(), organization) : null;
            GroupResponse result = access.execute(sid, subject, context -> {
                SessionAccountGrant grant = authorize(context, request.accountId(), organization, true, request.type(),canaryDecision);
                if (canaryDecision != null) canary.revalidate(canaryDecision, context, request.accountId(), organization);
                Optional<GroupRepository.Creation> existing = groups.creation(organization, request.accountId(), request.requestId());
                if (existing.isPresent()) {
                    if (!existing.get().fingerprint().equals(fingerprint)) throw new GroupFailure(HttpStatus.CONFLICT);
                    GroupResponse retry = read(organization, existing.get().id());
                    sessions.touch(context.session(), grant, context.now());
                    return retry;
                }
                if (request.parentGroupId() != null) {
                    GroupRepository.Visible parent = groups.find(organization, request.parentGroupId()).orElseThrow(GroupService::denied);
                    if (parent.depth() >= 32) throw new GroupFailure(HttpStatus.BAD_REQUEST);
                }
                Group group = new Group(UUID.randomUUID(), organization, request.parentGroupId(), name, request.type(),
                        request.accountId(), request.requestId(), fingerprint, context.now());
                groups.create(group);
                sessions.audit(context.owner().userId(), request.accountId(), sid, "GROUP_CREATED", context.now());
                outbox.groupCreated(group.id(), organization, group.parentGroupId(), context.now());
                sessions.touch(context.session(), grant, context.now());
                return read(organization, group.id());
            });
            outcome("succeeded");
            return result;
        } catch (DataIntegrityViolationException conflict) {
            outcome("conflict");
            throw new GroupFailure(HttpStatus.CONFLICT);
        } catch (com.unidocs.auth.authorization.application.OperationAuthorizationFailure failure) {
            outcome("denied");
            throw new GroupFailure(failure.status());
        } catch (GroupFailure failure) {
            outcome("denied");
            throw failure;
        }
    }

    public GroupResponse get(UUID sid, UUID subject, UUID account, UUID organization, UUID group) {
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision=
                canary!=null && canary.applies(organization)?canary.check(sid,subject,account,organization):null;
        return access.execute(sid, subject, context -> {
            SessionAccountGrant grant = authorize(context, account, organization, false,null,canaryDecision);
            if(canaryDecision!=null)canary.revalidate(canaryDecision,context,account,organization);
            GroupResponse result = read(organization, group);
            sessions.touch(context.session(), grant, context.now());
            return result;
        });
    }

    public record Page(List<GroupResponse> groups, UUID nextCursor) { }
    public Page list(UUID sid, UUID subject, UUID account, UUID organization, UUID after, int limit) {
        if (limit < 1 || limit > 100) throw new GroupFailure(HttpStatus.BAD_REQUEST);
        com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision canaryDecision=
                canary!=null && canary.applies(organization)?canary.check(sid,subject,account,organization):null;
        return access.execute(sid, subject, context -> {
            SessionAccountGrant grant = authorize(context, account, organization, false,null,canaryDecision);
            if(canaryDecision!=null)canary.revalidate(canaryDecision,context,account,organization);
            List<GroupResponse> rows = groups.list(organization, after, limit + 1);
            boolean more = rows.size() > limit;
            List<GroupResponse> page = List.copyOf(rows.subList(0, Math.min(limit, rows.size())));
            sessions.touch(context.session(), grant, context.now());
            return new Page(page, more ? page.getLast().id() : null);
        });
    }

    private SessionAccountGrant authorize(SessionAccess.Context context, UUID account, UUID organization, boolean mutation) {
        return authorize(context,account,organization,mutation,null,null);
    }
    private SessionAccountGrant authorize(SessionAccess.Context context, UUID account, UUID organization, boolean mutation, Group.Type creationType) {
        return authorize(context,account,organization,mutation,creationType,null);
    }
    private SessionAccountGrant authorize(SessionAccess.Context context, UUID account, UUID organization, boolean mutation,
            Group.Type creationType,com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary.Decision decision) {
        SessionAccountGrant grant = sessions.liveGrant(context.session(), account, context.now()).orElseThrow(GroupService::denied);
        if (!Set.of("LOGIN", "PASSWORD").contains(grant.authMethod()) || !groups.lockOrganization(organization, mutation)) throw denied();
        OrganizationRepository.Visibility visibility = organizations.visibility(account, grant.authMethod(), organization).orElseThrow(GroupService::denied);
        if(organizations.university(organization)) throw denied();
        if(professional.professional(organization)) {
            if(canary!=null)canary.requireDecision(organization,null,"organization.group.create",decision);
            try { if(decision==null || !decision.enforcing())
                professional.require(context,account,organization,null,"auth-service","organization.group.create"); }
            catch(com.unidocs.auth.authorization.application.OperationAuthorizationFailure failure) { throw new GroupFailure(failure.status()); }
            if(creationType==Group.Type.COURSE || creationType==Group.Type.CLASS) throw denied();
            return grant;
        }
        if (visibility.role() != OrganizationMembership.Role.OWNER && visibility.role() != OrganizationMembership.Role.ADMIN
                && !(mutation && (creationType==Group.Type.COURSE || creationType==Group.Type.DEPARTMENT)
                    && organizations.instituteCurator(organization,visibility.membershipId()))) throw denied();
        return grant;
    }
    private GroupResponse read(UUID organization, UUID group) {
        return groups.find(organization, group).orElseThrow(GroupService::denied).group();
    }
    private static GroupFailure denied() { return new GroupFailure(HttpStatus.FORBIDDEN); }
    private void outcome(String outcome) { metrics.counter("group.bootstrap", "outcome", outcome).increment(); }
    private static String fingerprint(String name, GroupRequest request) {
        String canonical = name + "\n" + request.type().name() + "\n" + request.parentGroupId();
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException unavailable) { throw new IllegalStateException(unavailable); }
    }
}
