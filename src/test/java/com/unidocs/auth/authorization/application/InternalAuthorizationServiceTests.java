package com.unidocs.auth.authorization.application;

import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.authorization.api.InternalAuthorizationRequest;
import com.unidocs.auth.authorization.api.InternalAuthorizationResponse;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.domain.UserSession;
import com.unidocs.auth.session.persistence.SessionRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class InternalAuthorizationServiceTests {
    private final JwtDecoder decoder = mock(JwtDecoder.class);
    private final SessionAccess access = mock(SessionAccess.class);
    private final SessionRepository sessions = mock(SessionRepository.class);
    private final OrganizationRepository organizations = mock(OrganizationRepository.class);
    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();
    private final com.unidocs.auth.group.persistence.GroupMembershipRepository groups = mock(com.unidocs.auth.group.persistence.GroupMembershipRepository.class);
    private final com.unidocs.auth.student.StudentAuthorization students=mock(com.unidocs.auth.student.StudentAuthorization.class);
    private final InternalAuthorizationService authorization = new InternalAuthorizationService(decoder, access, sessions, organizations, metrics, groups,students);
    private final UUID subject = UUID.randomUUID();
    private final UUID sessionId = UUID.randomUUID();
    private final UUID organizationId = UUID.randomUUID();
    private final Instant decodedAt = Instant.parse("2026-10-09T12:00:00Z");
    private final Instant expiration = decodedAt.plusSeconds(1);
    private final UserSession session = new UserSession(sessionId, UUID.randomUUID(), subject, "ACTIVE", decodedAt,
            decodedAt, decodedAt.plusSeconds(3600), null);

    @BeforeEach
    void decoderAcceptsTokenBeforeLockAcquisition() {
        Jwt jwt = Jwt.withTokenValue("delegated").header("alg", "RS256").subject(subject.toString())
                .claim("sid", sessionId.toString()).issuedAt(decodedAt.minusSeconds(60)).expiresAt(expiration).build();
        when(decoder.decode("delegated")).thenReturn(jwt);
    }

    @SuppressWarnings("unchecked")
    private void lockAcquiredAt(Instant now) {
        doAnswer(invocation -> {
            Function<SessionAccess.Context, InternalAuthorizationResponse> operation = invocation.getArgument(2);
            return operation.apply(new SessionAccess.Context(session, null, null, now));
        }).when(access).execute(eq(sessionId), eq(subject), any());
    }

    @ParameterizedTest
    @ValueSource(longs = {0, 1})
    void tokenExpiredDuringLockWaitCannotReadEntitlementsOrTouchSession(long secondsAfterExpiry) {
        lockAcquiredAt(expiration.plusSeconds(secondsAfterExpiry));
        assertThatThrownBy(() -> authorization.authorize("Bearer delegated", new InternalAuthorizationRequest(subject, organizationId)))
                .isInstanceOf(AuthenticationFailure.class);
        verifyNoInteractions(sessions, organizations, groups);
        assertThat(metrics.get("authorization.internal").tag("outcome", "unauthenticated").timer().count()).isEqualTo(1);
    }

    @Test
    void tokenStillValidAfterLockAcquisitionUsesCurrentEntitlement() {
        lockAcquiredAt(decodedAt);
        SessionAccountGrant grant = new SessionAccountGrant(sessionId, subject, "ACTIVE", "LOGIN", 1,
                decodedAt.plusSeconds(1800), decodedAt.plusSeconds(3600));
        UUID membershipId = UUID.randomUUID();
        when(sessions.liveGrant(session, subject, decodedAt)).thenReturn(Optional.of(grant));
        when(organizations.visibility(subject, "LOGIN", organizationId)).thenReturn(Optional.of(
                new OrganizationRepository.Visibility(membershipId, OrganizationMembership.Role.MEMBER, 2, 3)));
        InternalAuthorizationResponse result = authorization.authorize("Bearer delegated", new InternalAuthorizationRequest(subject, organizationId));
        assertThat(result.membershipId()).isEqualTo(membershipId);
        assertThat(result.membershipVersion()).isEqualTo(2);
        assertThat(result.authorizationVersion()).isEqualTo(3);
        assertThat(result.checkedAt()).isEqualTo(decodedAt);
        assertThat(result.expiresAt()).isEqualTo(decodedAt);
        verify(sessions).touch(session, grant, decodedAt);
        assertThat(metrics.get("authorization.internal").tag("outcome", "allowed").timer().count()).isEqualTo(1);
    }
}
