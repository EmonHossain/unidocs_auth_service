package com.unidocs.auth.authorization.application;

import java.util.UUID;
import java.util.List;
import java.util.function.Function;
import com.unidocs.auth.authorization.api.InternalAccountAuthorizationRequest;
import com.unidocs.auth.authorization.api.InternalAccountAuthorizationResponse;
import com.unidocs.auth.authorization.api.InternalGroupAuthorizationRequest;
import com.unidocs.auth.authorization.api.InternalGroupAuthorizationResponse;
import com.unidocs.auth.group.domain.GroupMembership;
import com.unidocs.auth.group.persistence.GroupMembershipRepository;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.authorization.api.InternalAuthorizationRequest;
import com.unidocs.auth.authorization.api.InternalAuthorizationResponse;
import com.unidocs.auth.organization.application.OrganizationFailure;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(propagation = Propagation.NEVER)
public class InternalAuthorizationService {
    private final JwtDecoder users;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final OrganizationRepository organizations;
    private final MeterRegistry metrics;
    private final GroupMembershipRepository groups;
    private final com.unidocs.auth.student.StudentAuthorization students;

    public InternalAuthorizationService(@Qualifier("jwtDecoder") JwtDecoder users, SessionAccess access,
            SessionRepository sessions, OrganizationRepository organizations, MeterRegistry metrics,
            GroupMembershipRepository groups,com.unidocs.auth.student.StudentAuthorization students) {
        this.students=students;
        this.users = users;
        this.access = access;
        this.sessions = sessions;
        this.organizations = organizations;
        this.metrics = metrics;
        this.groups = groups;
    }

    public InternalAuthorizationResponse authorize(String delegatedAuthorization, InternalAuthorizationRequest request) {
        return execute(delegatedAuthorization, context -> {
            SessionAccountGrant grant = grant(context, request.accountId());
            OrganizationRepository.Visibility visibility = visibility(grant, request.organizationId());
            sessions.touch(context.session(), grant, context.now());
            return evidence(context, grant, request.organizationId(), visibility);
        });
    }

    public InternalAccountAuthorizationResponse authorizeAccount(String delegatedAuthorization,
            InternalAccountAuthorizationRequest request) {
        return execute(delegatedAuthorization, context -> {
            SessionAccountGrant grant = grant(context, request.accountId());
            String accountType = sessions.accountType(context.session(), grant.accountId())
                    .orElseThrow(InternalAuthorizationService::denied);
            sessions.touch(context.session(), grant, context.now());
            return new InternalAccountAuthorizationResponse(grant.accountId(), context.owner().userId(), context.session().id(),
                    grant.authMethod(), grant.credentialVersion(), context.now(), context.now(), accountType,
                    "UNIVERSITY".equals(accountType)?students.institution(grant.accountId()):null);
        });
    }

    public InternalGroupAuthorizationResponse authorizeGroup(String delegatedAuthorization,
            InternalGroupAuthorizationRequest request) {
        return execute(delegatedAuthorization, context -> {
            SessionAccountGrant grant = grant(context, request.accountId());
            OrganizationRepository.Visibility visibility = visibility(grant, request.organizationId());
            if(students.institutional(request.organizationId())) {
                students.require(context,request.accountId(),request.organizationId(),request.groupId(),"document-service","workspace.read");
                com.unidocs.auth.student.StudentAuthorization.GroupSnapshot studentGroup=students.groupSnapshot(request.organizationId(),request.groupId(),request.accountId());
                return new InternalGroupAuthorizationResponse(evidence(context,grant,request.organizationId(),visibility),request.groupId(),studentGroup.id(),studentGroup.role(),studentGroup.version());
            }
            List<GroupMembershipRepository.Row> memberships = groups.list(request.organizationId(), request.groupId(),
                    visibility.membershipId(), null, 2, context.now());
            if (memberships.size() != 1 || !memberships.getFirst().organizationAvailable()) throw denied();
            GroupMembership membership = memberships.getFirst().membership();
            sessions.touch(context.session(), grant, context.now());
            return new InternalGroupAuthorizationResponse(evidence(context, grant, request.organizationId(), visibility),
                    request.groupId(), membership.id(), membership.role(), membership.version());
        });
    }

    private SessionAccountGrant grant(SessionAccess.Context context, UUID account) {
        return sessions.liveGrant(context.session(), account, context.now()).orElseThrow(InternalAuthorizationService::denied);
    }

    private OrganizationRepository.Visibility visibility(SessionAccountGrant grant, UUID organization) {
        return organizations.visibility(grant.accountId(), grant.authMethod(), organization)
                .orElseThrow(InternalAuthorizationService::denied);
    }

    private InternalAuthorizationResponse evidence(SessionAccess.Context context, SessionAccountGrant grant,
            UUID organization, OrganizationRepository.Visibility visibility) {
        return new InternalAuthorizationResponse(grant.accountId(), organization, visibility.membershipId(),
                visibility.role(), visibility.membershipVersion(), visibility.authorizationVersion(), context.now(), context.now());
    }

    private <T> T execute(String delegatedAuthorization, Function<SessionAccess.Context, T> operation) {
        io.micrometer.core.instrument.Timer.Sample sample = io.micrometer.core.instrument.Timer.start(metrics);
        String outcome = "unavailable";
        try {
            Jwt user = delegatedUser(delegatedAuthorization);
            UUID sessionId = UUID.fromString(user.getClaimAsString("sid"));
            UUID subject = UUID.fromString(user.getSubject());
            T response = access.execute(sessionId, subject, context -> {
                // Lock contention must not extend the delegated access-token lifetime.
                if (!user.getExpiresAt().isAfter(context.now())) throw new AuthenticationFailure();
                return operation.apply(context);
            });
            outcome = "allowed";
            return response;
        } catch (AuthenticationFailure failure) {
            outcome = "unauthenticated";
            throw failure;
        } catch (OrganizationFailure failure) {
            outcome = "denied";
            throw failure;
        } finally {
            sample.stop(metrics.timer("authorization.internal", "outcome", outcome));
        }
    }

    private Jwt delegatedUser(String header) {
        if (header == null || !header.startsWith("Bearer ") || header.length() > 8192
                || header.length() <= 7 || header.substring(7).chars().anyMatch(Character::isWhitespace)) {
            throw new AuthenticationFailure();
        }
        try {
            return users.decode(header.substring(7));
        } catch (JwtException | IllegalArgumentException failure) {
            throw new AuthenticationFailure();
        }
    }

    private static OrganizationFailure denied() { return new OrganizationFailure(HttpStatus.FORBIDDEN); }
}
