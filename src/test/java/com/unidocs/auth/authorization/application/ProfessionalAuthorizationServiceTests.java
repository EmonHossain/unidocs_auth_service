package com.unidocs.auth.authorization.application;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.UserSession;
import com.unidocs.auth.session.persistence.SessionRepository;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ProfessionalAuthorizationServiceTests {
    /**
     * Prevents direct facade calls from authorizing any graph-selected management operation through SQL.
     * @param operation registered management operation
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
            "organization.group.create", "organization.employee.create", "organization.employee.remove",
            "organization.employee.reset", "organization.responsibility.assign", "organization.access.update",
            "organization.department.assign", "organization.group.assign", "organization.group.unassign",
            "department.access.update", "team.access.update", "organization.collaboration.invite"
    })
    void sqlFacadeRejectsEveryEnforcedManagementOperation(String operation) {
        UUID organization=UUID.randomUUID(),account=UUID.randomUUID(),group=UUID.randomUUID();
        @SuppressWarnings("unchecked") org.springframework.beans.factory.ObjectProvider<ProfessionalSpiceDbCanary> provider=
                mock(org.springframework.beans.factory.ObjectProvider.class);
        ProfessionalAuthorizationService current=new ProfessionalAuthorizationService(jdbc,sessions,organizations,policies,
                Clock.fixed(now,ZoneOffset.UTC),provider);
        com.unidocs.auth.security.spicedb.SpiceDbPermissionClient graph=mock(com.unidocs.auth.security.spicedb.SpiceDbPermissionClient.class);
        ProfessionalSpiceDbCanary canary=new ProfessionalSpiceDbCanary(organization.toString(),false,true,true,
                mock(SessionAccess.class),current,policies,graph,jdbc,Clock.fixed(now,ZoneOffset.UTC),
                new io.micrometer.core.instrument.simple.SimpleMeterRegistry());
        when(provider.getIfAvailable()).thenReturn(canary);
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        for(org.assertj.core.api.ThrowableAssert.ThrowingCallable call:java.util.List.<org.assertj.core.api.ThrowableAssert.ThrowingCallable>of(
                ()->current.require(context,account,organization,group,"auth-service",operation),
                ()->current.require(context,account,organization,group,"auth-service",operation,false),
                ()->current.preview(context,account,organization,group,"auth-service",operation))) {
            assertThatThrownBy(call).isInstanceOfSatisfying(OperationAuthorizationFailure.class,
                    failure->assertThat(failure.status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
        }
        verifyNoInteractions(jdbc,sessions,organizations,policies,graph);
    }

    /**
     * Keeps the existing IAM admission path for shadow mode, other cohorts and unmigrated content.
     * @param mode server-side selection that must retain legacy evaluation
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings={"DISABLED","SHADOW","OTHER_COHORT","CONTENT"})
    void facadePreservesUnmigratedAdmission(String mode) {
        UUID organization=UUID.randomUUID(),account=UUID.randomUUID();
        @SuppressWarnings("unchecked") org.springframework.beans.factory.ObjectProvider<ProfessionalSpiceDbCanary> provider=
                mock(org.springframework.beans.factory.ObjectProvider.class);
        ProfessionalAuthorizationService current=new ProfessionalAuthorizationService(jdbc,sessions,organizations,policies,
                Clock.fixed(now,ZoneOffset.UTC),provider);
        if(!mode.equals("DISABLED")) when(provider.getIfAvailable()).thenReturn(new ProfessionalSpiceDbCanary(
                (mode.equals("OTHER_COHORT")?UUID.randomUUID():organization).toString(),false,true,!mode.equals("SHADOW"),
                mock(SessionAccess.class),current,policies,mock(com.unidocs.auth.security.spicedb.SpiceDbPermissionClient.class),
                jdbc,Clock.fixed(now,ZoneOffset.UTC),new io.micrometer.core.instrument.simple.SimpleMeterRegistry()));
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        assertThatThrownBy(()->current.require(context,account,organization,null,mode.equals("CONTENT")?"document-service":"auth-service",
                mode.equals("CONTENT")?"workspace.read":"organization.group.create"))
                .isInstanceOfSatisfying(OperationAuthorizationFailure.class,
                        failure->assertThat(failure.status()).isEqualTo(HttpStatus.FORBIDDEN));
        verify(sessions).liveGrant(null,account,now);
        verifyNoInteractions(jdbc,organizations,policies);
    }

    /**
     * Exercises the real Spring completion callback and rollback decision for every captured deadline.
     * @param deadline eligibility deadline under test
     * @param offset completion time relative to that deadline
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "SESSION,-1", "SESSION,0", "SESSION,1", "IDLE,-1", "IDLE,0", "IDLE,1",
            "ABSOLUTE,-1", "ABSOLUTE,0", "ABSOLUTE,1", "PROJECTION,-1", "PROJECTION,0", "PROJECTION,1"
    })
    void transactionCompletionRollsBackAtCapturedDeadline(String deadline, long offset) {
        Instant boundary=now.plusSeconds(60);
        java.util.concurrent.atomic.AtomicReference<Instant> time=new java.util.concurrent.atomic.AtomicReference<>(now);
        Clock clock=mock(Clock.class);
        when(clock.instant()).thenAnswer(call->time.get());
        ProfessionalAuthorizationService current=new ProfessionalAuthorizationService(jdbc,sessions,organizations,policies,clock);
        UUID selectedAccount=UUID.randomUUID(),loginAccount=UUID.randomUUID();
        UserSession session=new UserSession(UUID.randomUUID(),UUID.randomUUID(),loginAccount,"ACTIVE",now,now,
                deadline.equals("SESSION")?boundary:now.plusSeconds(3600),null);
        com.unidocs.auth.session.domain.SessionAccountGrant sustaining=new com.unidocs.auth.session.domain.SessionAccountGrant(
                session.id(),loginAccount,"ACTIVE","LOGIN",1,now.plusSeconds(3600),now.plusSeconds(3600));
        com.unidocs.auth.session.domain.SessionAccountGrant selected=new com.unidocs.auth.session.domain.SessionAccountGrant(
                session.id(),selectedAccount,"ACTIVE","PASSWORD",1,deadline.equals("IDLE")?boundary:now.plusSeconds(3600),
                deadline.equals("ABSOLUTE")?boundary:now.plusSeconds(3600));
        SessionAccess.Context context=new SessionAccess.Context(session,null,sustaining,now);
        when(sessions.liveGrant(session,selectedAccount,now)).thenReturn(Optional.of(selected));
        RecordingTransactions manager=new RecordingTransactions();
        org.springframework.transaction.support.TransactionTemplate transaction=new org.springframework.transaction.support.TransactionTemplate(manager);
        org.assertj.core.api.ThrowableAssert.ThrowingCallable operation=()->transaction.execute(status->{
            current.guardTransactionCompletion(context,selectedAccount,deadline.equals("PROJECTION")?boundary:null);
            time.set(boundary.plusSeconds(offset));
            return "protected-result";
        });
        if(offset<0) assertThatCode(operation).doesNotThrowAnyException();
        else assertThatThrownBy(operation).isInstanceOfSatisfying(OperationAuthorizationFailure.class,
                failure->assertThat(failure.status()).isEqualTo(deadline.equals("PROJECTION")
                        ?HttpStatus.SERVICE_UNAVAILABLE:HttpStatus.FORBIDDEN));
        assertThat(manager.commits).isEqualTo(offset<0?1:0);
        assertThat(manager.rollbacks).isEqualTo(offset<0?0:1);
        verify(sessions).liveGrant(session,selectedAccount,now);
        verifyNoMoreInteractions(sessions);
        verifyNoInteractions(jdbc,organizations,policies);
        assertThat(org.springframework.transaction.support.TransactionSynchronizationManager.isSynchronizationActive()).isFalse();
    }

    /** Rejects use outside a synchronized transaction before looking up an account grant. */
    @Test void completionGuardRequiresTransaction() {
        assertThatThrownBy(()->service.guardTransactionCompletion(mock(SessionAccess.Context.class),UUID.randomUUID(),null))
                .isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(sessions,jdbc,organizations,policies);
    }

    /** A clock regression during domain work must roll back even if every expiry remains in the future. */
    @Test void completionGuardRejectsClockRegression() {
        Clock clock=mock(Clock.class);
        when(clock.instant()).thenReturn(now,now,now.minusNanos(1));
        ProfessionalAuthorizationService current=new ProfessionalAuthorizationService(jdbc,sessions,organizations,policies,clock);
        UUID account=UUID.randomUUID();
        UserSession session=new UserSession(UUID.randomUUID(),UUID.randomUUID(),account,"ACTIVE",now,now,now.plusSeconds(3600),null);
        com.unidocs.auth.session.domain.SessionAccountGrant grant=new com.unidocs.auth.session.domain.SessionAccountGrant(
                session.id(),account,"ACTIVE","LOGIN",1,now.plusSeconds(3600),now.plusSeconds(3600));
        when(sessions.liveGrant(session,account,now)).thenReturn(Optional.of(grant));
        RecordingTransactions manager=new RecordingTransactions();
        org.springframework.transaction.support.TransactionTemplate transaction=new org.springframework.transaction.support.TransactionTemplate(manager);
        assertThatThrownBy(()->transaction.execute(status->{
            current.guardTransactionCompletion(new SessionAccess.Context(session,null,grant,now),account,null);
            return true;
        })).isInstanceOfSatisfying(OperationAuthorizationFailure.class,
                failure->assertThat(failure.status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
        assertThat(manager.commits).isZero();
        assertThat(manager.rollbacks).isEqualTo(1);
        verifyNoInteractions(jdbc,organizations,policies);
    }

    /** Records Spring's actual commit/rollback selection without database or infrastructure side effects. */
    private static final class RecordingTransactions extends org.springframework.transaction.support.AbstractPlatformTransactionManager {
        private int commits;
        private int rollbacks;
        /** {@inheritDoc} */
        @Override protected Object doGetTransaction() { return new Object(); }
        /** {@inheritDoc} */
        @Override protected void doBegin(Object transaction,org.springframework.transaction.TransactionDefinition definition) { }
        /** {@inheritDoc} */
        @Override protected void doCommit(org.springframework.transaction.support.DefaultTransactionStatus status) { commits++; }
        /** {@inheritDoc} */
        @Override protected void doRollback(org.springframework.transaction.support.DefaultTransactionStatus status) { rollbacks++; }
    }
    /**
     * Ensures every management policy still requires a current selected-account grant.
     * @param operation registered management operation
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
            "organization.group.create", "organization.employee.create", "organization.employee.remove",
            "organization.employee.reset", "organization.responsibility.assign", "organization.access.update",
            "organization.department.assign", "organization.group.assign", "organization.group.unassign",
            "department.access.update", "team.access.update", "organization.collaboration.invite"
    })
    void graphWitnessNeverOverridesRevokedSelectedGrant(String operation) {
        UUID account = UUID.randomUUID(), organization = UUID.randomUUID();
        SessionAccess.Context context = mock(SessionAccess.Context.class);
        assertThatThrownBy(() -> service.requireGraph(context, account, organization, null,
                "auth-service", operation, java.util.Set.of(UUID.randomUUID())))
                .isInstanceOfSatisfying(OperationAuthorizationFailure.class,
                        failure -> assertThat(failure.status()).isEqualTo(HttpStatus.FORBIDDEN));
        verifyNoInteractions(jdbc, organizations, policies);
        verify(sessions, never()).touch(any(), any(), any());
    }

    /**
     * Checks session, idle-grant and absolute-grant expiry independently after a lock wait.
     * @param expiring eligibility deadline under test
     * @param secondsAfterExpiry lock acquisition offset from that deadline
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "SESSION,-1", "SESSION,0", "SESSION,1", "IDLE_GRANT,-1", "IDLE_GRANT,0", "IDLE_GRANT,1",
            "ABSOLUTE_GRANT,-1", "ABSOLUTE_GRANT,0", "ABSOLUTE_GRANT,1"
    })
    void finalGrantLockWaitDoesNotExtendSessionOrSelectedGrantExpiry(String expiring, long secondsAfterExpiry) {
        Instant boundary = now.plusSeconds(60);
        Clock changingClock = mock(Clock.class);
        when(changingClock.instant()).thenReturn(now, boundary.plusSeconds(secondsAfterExpiry));
        ProfessionalAuthorizationService current = new ProfessionalAuthorizationService(jdbc, sessions, organizations,
                policies, changingClock);
        UUID account = UUID.randomUUID();
        UserSession session = new UserSession(UUID.randomUUID(), UUID.randomUUID(), account, "ACTIVE",
                now, now, expiring.equals("SESSION") ? boundary : now.plusSeconds(3600), null);
        com.unidocs.auth.session.domain.SessionAccountGrant grant = new com.unidocs.auth.session.domain.SessionAccountGrant(
                session.id(), account, "ACTIVE", "LOGIN", 1,
                expiring.equals("IDLE_GRANT") ? boundary : now.plusSeconds(3600),
                expiring.equals("ABSOLUTE_GRANT") ? boundary : now.plusSeconds(3600));
        SessionAccess.Context context = new SessionAccess.Context(session, null, grant, now);
        when(sessions.liveGrant(session, account, now)).thenReturn(Optional.of(grant));

        if (secondsAfterExpiry < 0) assertThatCode(() -> current.revalidateGrant(context, account)).doesNotThrowAnyException();
        else assertThatThrownBy(() -> current.revalidateGrant(context, account)).isInstanceOf(OperationAuthorizationFailure.class);
        verifyNoInteractions(jdbc, organizations, policies);
        verify(sessions, never()).touch(any(), any(), any());
    }

    private final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    private final SessionRepository sessions=mock(SessionRepository.class);
    private final OrganizationRepository organizations=mock(OrganizationRepository.class);
    private final OperationPolicyCatalogRepository policies=mock(OperationPolicyCatalogRepository.class);
    private final Instant now=Instant.parse("2026-10-16T12:00:00Z");
    private final ProfessionalAuthorizationService service=new ProfessionalAuthorizationService(jdbc,sessions,organizations,policies,Clock.fixed(now,ZoneOffset.UTC));

    @Test void lockedSelectedAccountCannotUseOrganizationResponsibilities() {
        UUID account=UUID.randomUUID();UUID org=UUID.randomUUID();UUID sid=UUID.randomUUID();
        UserSession session=new UserSession(sid,UUID.randomUUID(),account,"ACTIVE",now,now,now.plusSeconds(3600),null);
        SessionAccess.Context context=new SessionAccess.Context(session,new SessionRepository.Owner(UUID.randomUUID(),"Synthetic",account),null,now);
        when(sessions.liveGrant(session,account,now)).thenReturn(Optional.empty());
        assertThatThrownBy(()->service.require(context,account,org,null,"auth-service","organization.employee.create"))
                .isInstanceOfSatisfying(OperationAuthorizationFailure.class,failure->assertThat(failure.status()).isEqualTo(HttpStatus.FORBIDDEN));
        verifyNoInteractions(jdbc,organizations,policies);
    }

    @Test void studentOrganizationsNeverEnterProfessionalMatching() {
        UUID org=UUID.randomUUID();
        when(jdbc.queryForObject(anyString(),eq(Boolean.class),any(Object[].class))).thenReturn(false);
        assertThat(service.professional(org)).isFalse();
        verifyNoInteractions(sessions,organizations,policies);
    }

    @Test void unavailableCurrentStateNeverFallsBackToRoleNameOrCachedAllow() {
        when(jdbc.queryForObject(anyString(),eq(Boolean.class),any(Object[].class))).thenThrow(new DataAccessResourceFailureException("unavailable"));
        assertThatThrownBy(()->service.professional(UUID.randomUUID())).isInstanceOf(DataAccessResourceFailureException.class);
        verifyNoInteractions(sessions,organizations,policies);
    }

    @Test void organizationScopeHasNoFabricatedGroupAncestor() {
        assertThat(service.ancestors(UUID.randomUUID(),null)).isEmpty();
        verifyNoInteractions(jdbc);
    }

    @Test void missingOrForeignGroupFailsClosed() {
        when(jdbc.query(anyString(),org.mockito.ArgumentMatchers.<RowMapper<Object>>any(),any(Object[].class))).thenReturn(java.util.List.of());
        assertThatThrownBy(()->service.ancestors(UUID.randomUUID(),UUID.randomUUID())).isInstanceOf(OperationAuthorizationFailure.class);
    }
}
