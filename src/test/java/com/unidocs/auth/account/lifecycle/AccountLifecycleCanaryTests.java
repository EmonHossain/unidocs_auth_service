package com.unidocs.auth.account.lifecycle;

import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import com.unidocs.auth.authorization.application.ProfessionalAuthorizationService;
import com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary;
import com.unidocs.auth.group.personal.PersonalAccountDeparture;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** All administrative lifecycle entry paths must revalidate before notices, revocation or outbox writes. */
class AccountLifecycleCanaryTests {
    private final UUID sid = UUID.randomUUID(), subject = UUID.randomUUID(), org = UUID.randomUUID();
    private final UUID actor = UUID.randomUUID(), membership = UUID.randomUUID(), target = UUID.randomUUID();
    private final UUID user = UUID.randomUUID(), group = UUID.randomUUID(), request = UUID.randomUUID();
    private final Instant now = Instant.parse("2026-10-31T12:00:00Z");
    private final LifecycleRepository store = mock(LifecycleRepository.class);
    private final SessionAccess access = mock(SessionAccess.class);
    private final SessionAccess.Context context = mock(SessionAccess.Context.class);
    private final SessionRepository sessions = mock(SessionRepository.class);
    private final OrganizationRepository organizations = mock(OrganizationRepository.class);
    private final OrganizationSnapshotStore snapshots = mock(OrganizationSnapshotStore.class);
    private final OutboxRepository outbox = mock(OutboxRepository.class);
    private final AccountNoticeDelivery delivery = mock(AccountNoticeDelivery.class);
    private final ProfessionalAuthorizationService professional = mock(ProfessionalAuthorizationService.class);
    private final ProfessionalSpiceDbCanary canary = mock(ProfessionalSpiceDbCanary.class);
    private final ProfessionalSpiceDbCanary.Decision decision = mock(ProfessionalSpiceDbCanary.Decision.class);
    private AccountLifecycleService service;

    /** Wires a selected graph decision that becomes stale before the final transaction. */
    @BeforeEach
    void configure() {
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        service = new AccountLifecycleService(store, access, sessions, organizations, snapshots, outbox,
                new RetentionPolicy(3), delivery, mock(PasswordEncoder.class), Clock.systemUTC(),
                new SimpleMeterRegistry(), mock(PlatformTransactionManager.class), mock(PersonalAccountDeparture.class),
                professional, provider);
        when(canary.applies(org, "organization.employee.remove")).thenReturn(true);
        when(canary.check(sid, subject, actor, org, "organization.employee.remove")).thenReturn(decision);
        when(decision.enforcing()).thenReturn(true);
        when(canary.revalidate(decision, context, actor, org)).thenThrow(
                new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE, "SPICEDB_AUTHORIZATION_UNAVAILABLE"));
        when(context.now()).thenReturn(now);
        SessionAccountGrant grant = mock(SessionAccountGrant.class);
        when(grant.authMethod()).thenReturn("LOGIN");
        when(sessions.liveGrant(null, actor, now)).thenReturn(Optional.of(grant));
        when(organizations.visibility(actor, "LOGIN", org)).thenReturn(Optional.of(new OrganizationRepository.Visibility(
                UUID.randomUUID(), OrganizationMembership.Role.OWNER, 1, 1)));
        when(professional.professional(org)).thenReturn(true);
        when(access.executeForGroups(eq(sid), eq(subject), anyList(), any())).thenAnswer(call ->
                call.<Function<SessionAccess.Context, Object>>getArgument(3).apply(context));
        when(access.execute(eq(sid), eq(subject), any())).thenAnswer(call ->
                call.<Function<SessionAccess.Context, Object>>getArgument(2).apply(context));
    }

    /**
     * Rejects every administrative lifecycle action before its durable effects.
     * @param action removal, blacklist or restoration command
     */
    @ParameterizedTest
    @EnumSource(LifecycleRequests.Action.class)
    void staleDecisionCannotRemoveBlacklistOrRestore(LifecycleRequests.Action action) {
        when(store.member(org, membership)).thenReturn(Optional.of(
                new LifecycleRepository.Member(membership, target, user, group, "MEMBER")));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, assertThrows(OperationAuthorizationFailure.class,
                () -> service.adminAction(sid, subject, org, membership, new LifecycleRequests.AdminAction(actor,
                        action, now.plusSeconds(3600), "Synthetic acceptance", "proof"))).status());
        verify(store, times(1)).member(org, membership);
        noSideEffects();
    }

    /**
     * Requires a current decision for either removal-review outcome.
     * @param approve requested review outcome
     */
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void staleDecisionCannotApproveOrRejectRemoval(boolean approve) {
        when(store.removal(request, false)).thenReturn(Optional.of(
                new LifecycleRepository.Removal(request, target, user, org, "PENDING", now)));
        when(store.account(target, false)).thenReturn(Optional.of(new LifecycleRepository.Account(
                target, user, group, org, "COMPANY", "Synthetic", "ACTIVE", 1, null)));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, assertThrows(OperationAuthorizationFailure.class,
                () -> service.review(sid, subject, org, request, new LifecycleRequests.Review(actor, approve,
                        "Synthetic acceptance", "proof"))).status());
        verify(store, never()).removal(request, true);
        noSideEffects();
    }

    /**
     * Prevents protected queue reads on denial or dependency uncertainty.
     * @param status final authorization failure status
     */
    @ParameterizedTest
    @ValueSource(ints = {403, 503})
    void deniedDecisionCannotReadAdministrativeRemovalQueue(int status) {
        doThrow(new OperationAuthorizationFailure(HttpStatus.valueOf(status), "DENIED"))
                .when(canary).revalidate(decision, context, actor, org);
        assertEquals(status, assertThrows(OperationAuthorizationFailure.class,
                () -> service.removals(sid, subject, org, actor, null, 10)).status().value());
        verifyNoInteractions(store);
        noSideEffects();
    }

    /** Verifies every mutation family remains untouched when final graph revalidation fails. */
    private void noSideEffects() {
        verify(professional, never()).require(any(), any(), any(), any(), anyString(), anyString());
        verify(store, never()).restrict(any(), any(), any(), anyString(), any(), any());
        verify(store, never()).restoreRestriction(any(), any());
        verify(store, never()).notice(any(), anyString(), anyString(), any(), any());
        verify(store, never()).review(any(), any(), anyString(), any());
        verify(store, never()).bumpOrganization(any(), any());
        verify(sessions, never()).audit(any(), any(), any(), anyString(), any());
        verifyNoInteractions(outbox, snapshots, delivery);
    }
}
