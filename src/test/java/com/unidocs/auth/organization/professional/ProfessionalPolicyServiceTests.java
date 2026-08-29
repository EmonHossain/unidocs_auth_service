package com.unidocs.auth.organization.professional;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.authorization.application.ProfessionalAuthorizationService;
import com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.mockito.ArgumentMatchers;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ProfessionalPolicyServiceTests {
    /** Ensures target scope denial prevents responsibility, notice, audit and outbox writes at the direct service entry. */
    @Test void responsibilityActivationRequiresCurrentLockedTargetScopeMembership() {
        execute();
        UUID target=UUID.randomUUID(),group=UUID.randomUUID();
        when(jdbc.queryForObject(contains("authorization_version"),eq(Long.class),any(Object[].class))).thenReturn(7L);
        when(jdbc.query(contains("SELECT m.id FROM organization_membership"),ArgumentMatchers.<RowMapper<UUID>>any(),any(Object[].class)))
                .thenReturn(java.util.List.of(UUID.randomUUID()));
        when(jdbc.queryForObject(contains("SELECT IF(type="),eq(String.class),any(Object[].class))).thenReturn("TEAM");
        when(jdbc.queryForObject(contains("SELECT COUNT(*) FROM iam_professional_responsibility"),eq(Integer.class),any(Object[].class))).thenReturn(1);
        doThrow(new OperationAuthorizationFailure(HttpStatus.FORBIDDEN,"PROFESSIONAL_AUTHORITY_DENIED"))
                .when(authorization).requireScopeMember(org,group,target);
        ProfessionalPolicyService.Responsibility command=new ProfessionalPolicyService.Responsibility(actor,target,group,UUID.randomUUID(),true,null,7);
        assertThatThrownBy(()->service.responsibility(sid,subject,org,command)).isInstanceOf(OperationAuthorizationFailure.class);
        verify(authorization).requireScopeMember(org,group,target);
        verify(jdbc,never()).update(anyString(),any(Object[].class));
        verifyNoInteractions(outbox,sessions);
    }
    /**
     * Rejects stale graph decisions before any restriction or related durable side effect.
     * @param operation registered scope-management policy
     * @param grouped whether a department/team selector is required
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "organization.access.update, false", "department.access.update, true", "team.access.update, true"
    })
    void finalRestrictionDenialCannotWritePolicyAuditNoticeOrOutbox(String operation, boolean grouped) {
        SessionAccess.Context context = execute();
        UUID group = grouped ? UUID.randomUUID() : null;
        ProfessionalSpiceDbCanary canary = mock(ProfessionalSpiceDbCanary.class);
        ProfessionalSpiceDbCanary.Decision decision = mock(ProfessionalSpiceDbCanary.Decision.class);
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(canary.applies(org, "organization.access.update")).thenReturn(true);
        if (grouped) {
            when(jdbc.query(contains("SELECT type FROM iam_group"),
                    ArgumentMatchers.<RowMapper<String>>any(), any(Object[].class)))
                    .thenReturn(java.util.List.of(operation.startsWith("department.") ? "DEPARTMENT" : "TEAM"));
            when(jdbc.queryForObject(contains("SELECT IF(type="), eq(String.class), any(Object[].class)))
                    .thenReturn(operation);
        }
        when(canary.applies(org, operation)).thenReturn(true);
        when(canary.check(sid, subject, actor, org, group, operation)).thenReturn(decision);
        when(decision.enforcing()).thenReturn(true);
        when(jdbc.queryForObject(contains("authorization_version"), eq(Long.class), any(Object[].class))).thenReturn(7L);
        when(canary.revalidate(decision, context, actor, org)).thenThrow(
                new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE, "SPICEDB_AUTHORIZATION_UNAVAILABLE"));
        ProfessionalPolicyService guarded = new ProfessionalPolicyService(access, authorization, jdbc, sessions, outbox, provider);
        ProfessionalPolicyService.Restriction command = new ProfessionalPolicyService.Restriction(
                actor, null, group, UUID.randomUUID(), true, null, 7);

        assertThatThrownBy(() -> guarded.restriction(sid, subject, org, command))
                .isInstanceOfSatisfying(OperationAuthorizationFailure.class,
                        failure -> assertThat(failure.status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
        verify(authorization, never()).require(any(), any(), any(), any(), anyString(), anyString());
        verify(jdbc, never()).update(anyString(), any(Object[].class));
        verifyNoInteractions(outbox, sessions);
    }

    private final SessionAccess access=mock(SessionAccess.class);
    private final ProfessionalAuthorizationService authorization=mock(ProfessionalAuthorizationService.class);
    private final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    private final SessionRepository sessions=mock(SessionRepository.class);
    private final OutboxRepository outbox=mock(OutboxRepository.class);
    private final ProfessionalPolicyService service=new ProfessionalPolicyService(access,authorization,jdbc,sessions,outbox);
    private final UUID sid=UUID.randomUUID(),subject=UUID.randomUUID(),org=UUID.randomUUID(),actor=UUID.randomUUID();

    @SuppressWarnings("unchecked")
    private SessionAccess.Context execute() {
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        when(context.now()).thenReturn(Instant.parse("2026-10-16T12:00:00Z"));
        when(access.execute(eq(sid),eq(subject),any())).thenAnswer(call->call.<Function<SessionAccess.Context,Object>>getArgument(2).apply(context));
        return context;
    }
    @Test void staleMutationCannotOverwriteAConcurrentPolicyChange() {
        SessionAccess.Context context=execute();
        when(jdbc.queryForObject(contains("authorization_version"),eq(Long.class),any(Object[].class))).thenReturn(8L);
        ProfessionalPolicyService.Responsibility command=new ProfessionalPolicyService.Responsibility(actor,UUID.randomUUID(),null,UUID.randomUUID(),true,null,7);
        assertThatThrownBy(()->service.responsibility(sid,subject,org,command)).isInstanceOfSatisfying(OperationAuthorizationFailure.class,
                failure->assertThat(failure.status()).isEqualTo(HttpStatus.CONFLICT));
        verify(authorization).admit(context,actor,org);
        verify(authorization,never()).require(any(),any(),any(),any(),anyString(),anyString());
        verifyNoInteractions(outbox,sessions);
        verify(jdbc,never()).update(anyString(),any(Object[].class));
    }
    @Test void scopeDenialPreventsAssignmentAuditNoticeAndOutboxWrites() {
        SessionAccess.Context context=execute();
        when(jdbc.queryForObject(contains("authorization_version"),eq(Long.class),any(Object[].class))).thenReturn(7L);
        when(authorization.require(context,actor,org,null,"auth-service","organization.responsibility.assign"))
                .thenThrow(new OperationAuthorizationFailure(HttpStatus.FORBIDDEN,"DENIED"));
        ProfessionalPolicyService.Responsibility command=new ProfessionalPolicyService.Responsibility(actor,UUID.randomUUID(),null,UUID.randomUUID(),true,null,7);
        assertThatThrownBy(()->service.responsibility(sid,subject,org,command)).isInstanceOf(OperationAuthorizationFailure.class);
        verify(jdbc,never()).update(anyString(),any(Object[].class));
        verifyNoInteractions(outbox,sessions);
    }
    @Test void deniedScopeDoesNotExposeAccessCatalogOrProjectionStatus() {
        SessionAccess.Context context=execute();
        when(authorization.require(context,actor,org,null,"auth-service","organization.access.update"))
                .thenThrow(new OperationAuthorizationFailure(HttpStatus.FORBIDDEN,"DENIED"));
        assertThatThrownBy(()->service.accessCatalog(sid,subject,org,actor)).isInstanceOf(OperationAuthorizationFailure.class);
        assertThatThrownBy(()->service.projectionStatus(sid,subject,org,actor)).isInstanceOf(OperationAuthorizationFailure.class);
        verify(authorization,times(2)).admit(context,actor,org);
        verifyNoInteractions(jdbc);
    }
    @Test void missingProjectionStateFailsClosedAfterScopeAdmission() {
        execute();
        assertThatThrownBy(()->service.projectionStatus(sid,subject,org,actor))
                .isInstanceOfSatisfying(OperationAuthorizationFailure.class,
                        failure->assertThat(failure.status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
    }

    @Test void graphDenialPreventsDirectResponsibilityMutationEntry() {
        ProfessionalSpiceDbCanary canary=mock(ProfessionalSpiceDbCanary.class);
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider=mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(canary.applies(org,"organization.responsibility.assign")).thenReturn(true);
        when(canary.check(sid,subject,actor,org,null,"organization.responsibility.assign"))
                .thenThrow(new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE,"SPICEDB_AUTHORIZATION_UNAVAILABLE"));
        ProfessionalPolicyService guarded=new ProfessionalPolicyService(access,authorization,jdbc,sessions,outbox,provider);
        ProfessionalPolicyService.Responsibility command=new ProfessionalPolicyService.Responsibility(actor,UUID.randomUUID(),null,UUID.randomUUID(),true,null,7);

        assertThatThrownBy(()->guarded.responsibility(sid,subject,org,command))
                .isInstanceOfSatisfying(OperationAuthorizationFailure.class,
                        failure->assertThat(failure.status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
        verifyNoInteractions(access,authorization,jdbc,outbox,sessions);
    }

    @Test void enforcedGraphRevalidationDenialCannotFallBackToSqlAuthority() {
        SessionAccess.Context context=execute();
        ProfessionalSpiceDbCanary canary=mock(ProfessionalSpiceDbCanary.class);
        ProfessionalSpiceDbCanary.Decision decision=mock(ProfessionalSpiceDbCanary.Decision.class);
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider=mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(canary.applies(org,"organization.responsibility.assign")).thenReturn(true);
        when(canary.check(sid,subject,actor,org,null,"organization.responsibility.assign")).thenReturn(decision);
        when(decision.enforcing()).thenReturn(true);
        when(jdbc.queryForObject(contains("authorization_version"),eq(Long.class),any(Object[].class))).thenReturn(7L);
        when(canary.revalidate(decision,context,actor,org))
                .thenThrow(new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE,"SPICEDB_AUTHORIZATION_UNAVAILABLE"));
        ProfessionalPolicyService guarded=new ProfessionalPolicyService(access,authorization,jdbc,sessions,outbox,provider);
        ProfessionalPolicyService.Responsibility command=new ProfessionalPolicyService.Responsibility(actor,UUID.randomUUID(),null,UUID.randomUUID(),true,null,7);

        assertThatThrownBy(()->guarded.responsibility(sid,subject,org,command))
                .isInstanceOfSatisfying(OperationAuthorizationFailure.class,
                        failure->assertThat(failure.status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
        verify(authorization).admit(context,actor,org);
        verify(authorization,never()).require(any(),any(),any(),any(),anyString(),anyString());
        verify(jdbc,never()).update(anyString(),any(Object[].class));
        verifyNoInteractions(outbox,sessions);
    }
}
