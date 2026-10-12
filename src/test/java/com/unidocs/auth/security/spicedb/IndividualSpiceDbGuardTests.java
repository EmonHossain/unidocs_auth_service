package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.*;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.authorization.domain.*;
import io.grpc.Status;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Policy coherence and transaction-bound security tests, without database or user fixtures. */
class IndividualSpiceDbGuardTests {
    private final UUID account=UUID.randomUUID(), group=UUID.randomUUID(), first=new UUID(0,1), second=new UUID(0,2);
    private final MutableClock clock=new MutableClock();
    private final SpiceDbPermissionClient graph=mock(SpiceDbPermissionClient.class);
    private final IntentJdbc jdbc=new IntentJdbc();
    private final TransactionTemplate transactions=new TransactionTemplate(new LocalTransactions());
    private IndividualSpiceDbGuard guard;

    /** Supplies a check-only client and independent explicit cohort. */
    @BeforeEach void configure() {
        DefaultListableBeanFactory beans=new DefaultListableBeanFactory();beans.registerSingleton("graph",graph);
        guard=new IndividualSpiceDbGuard(jdbc,clock,beans.getBeanProvider(SpiceDbPermissionClient.class),
                new MockEnvironment().withProperty("auth.spicedb.individual.enabled","true")
                        .withProperty("auth.spicedb.individual.account-ids",account.toString()),new SimpleMeterRegistry());
        when(graph.checkPermission(any())).thenAnswer(call->{
            assertFalse(TransactionSynchronizationManager.isActualTransactionActive());
            return answer(true,"revision");
        });
    }

    /** Both match modes use the same authority UUIDs at one exact snapshot. */
    @ParameterizedTest @EnumSource(AuthorityMatchMode.class)
    void checksAllComponentsAtOnePinnedSnapshot(AuthorityMatchMode mode) {
        IndividualSpiceDbGuard.Input input=capture(candidate(mode,1),Set.of(first,second));
        IndividualSpiceDbGuard.Decision decision=guard.check(input,clock.instant().plusSeconds(60));
        assertEquals(Set.of(first,second),decision.authorities());
        org.mockito.ArgumentCaptor<CheckPermissionRequest> requests=org.mockito.ArgumentCaptor.forClass(CheckPermissionRequest.class);
        verify(graph,times(2)).checkPermission(requests.capture());
        assertTrue(requests.getAllValues().getFirst().getConsistency().getFullyConsistent());
        assertEquals("revision",requests.getAllValues().getLast().getConsistency().getAtExactSnapshot().getToken());
        transactions.executeWithoutResult(status->assertEquals(Set.of(first,second),guard.revalidate(input,decision)));
    }

    /** ANY_OF returns only the actual graph witness; ALL_OF cannot accept a partial result. */
    @ParameterizedTest @EnumSource(AuthorityMatchMode.class)
    void partialAuthorityResultsRetainMatchMode(AuthorityMatchMode mode) {
        when(graph.checkPermission(any())).thenAnswer(call->answer(
                call.<CheckPermissionRequest>getArgument(0).getResource().getObjectId().endsWith(first.toString()),"revision"));
        IndividualSpiceDbGuard.Input input=capture(candidate(mode,1),Set.of(first,second));
        if(mode==AuthorityMatchMode.ALL_OF) assertFailure(403,()->guard.check(input,clock.instant().plusSeconds(60)));
        else assertEquals(Set.of(first),guard.check(input,clock.instant().plusSeconds(60)).authorities());
    }

    /** Missing publication evidence cannot contact the graph or fall back to SQL. */
    @Test void unpublishedIntentFailsClosedBeforeRpc() {
        IndividualSpiceDbGuard.Input input=capture(candidate(AuthorityMatchMode.ALL_OF,1),Set.of(first,second));
        jdbc.applied=false;assertFailure(503,()->guard.check(input,clock.instant().plusSeconds(60)));verifyNoInteractions(graph);
    }

    /** Snapshot drift, absent revision and conditional decisions all fail closed. */
    @Test void incoherentAndIncompleteResponsesCannotAuthorize() {
        IndividualSpiceDbGuard.Input input=capture(candidate(AuthorityMatchMode.ALL_OF,1),Set.of(first,second));
        when(graph.checkPermission(any())).thenReturn(answer(true,"one"),answer(true,"two"));
        assertFailure(503,()->guard.check(input,clock.instant().plusSeconds(60)));
        when(graph.checkPermission(any())).thenReturn(CheckPermissionResponse.newBuilder()
                .setPermissionship(CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION).build());
        assertFailure(503,()->guard.check(input,clock.instant().plusSeconds(60)));
        when(graph.checkPermission(any())).thenReturn(CheckPermissionResponse.newBuilder().setCheckedAt(ZedToken.newBuilder().setToken("revision"))
                .setPermissionship(CheckPermissionResponse.Permissionship.PERMISSIONSHIP_CONDITIONAL_PERMISSION).build());
        assertFailure(503,()->guard.check(input,clock.instant().plusSeconds(60)));
    }

    /** An expired exact snapshot or a gateway outage never produces fallback authorization. */
    @Test void dependencyFailureAndExpiredSnapshotAreUnavailable() {
        IndividualSpiceDbGuard.Input input=capture(candidate(AuthorityMatchMode.ALL_OF,1),Set.of(first,second));
        for(Status status:List.of(Status.UNAVAILABLE,Status.OUT_OF_RANGE)) {
            reset(graph);when(graph.checkPermission(any())).thenThrow(status.asRuntimeException());
            assertFailure(503,()->guard.check(input,clock.instant().plusSeconds(60)));
        }
    }

    /** Current recapture fences group, policy and local authority changes, and omitted preflight. */
    @Test void changedDependenciesAndDirectEntryRejectEarlierWitness() {
        OperationPolicyCandidate policy=candidate(AuthorityMatchMode.ALL_OF,1);
        IndividualSpiceDbGuard.Input input=capture(policy,Set.of(first,second));
        IndividualSpiceDbGuard.Decision decision=guard.check(input,clock.instant().plusSeconds(60));
        for(IndividualSpiceDbGuard.Input changed:List.of(
                capture(candidate(AuthorityMatchMode.ALL_OF,2),Set.of(first,second)),capture(policy,Set.of(first)),
                transactions.execute(status->guard.capture(account,UUID.randomUUID(),policy,Set.of(first,second)))))
            assertFailure(503,()->transactions.executeWithoutResult(status->guard.revalidate(changed,decision)));
        assertFailure(503,()->transactions.executeWithoutResult(status->guard.revalidate(input,null)));
    }

    /** JWT expiry and operation duration are enforced by real Spring beforeCommit synchronization. */
    @Test void tokenAndCompletionDeadlinesCannotBeExtended() {
        IndividualSpiceDbGuard.Input input=capture(candidate(AuthorityMatchMode.ALL_OF,1),Set.of(first,second));
        IndividualSpiceDbGuard.Decision decision=guard.check(input,clock.instant().plusSeconds(1));
        assertFailure(503,()->transactions.executeWithoutResult(status->{guard.revalidate(input,decision);clock.now=clock.now.plusSeconds(2);}));
        assertFailure(503,()->guard.check(input,clock.instant().minusSeconds(1)));
    }

    /** SQL transactions cannot wrap graph calls; unavailable SQL is also fail-closed. */
    @Test void graphRpcCannotRunInsideSql() {
        IndividualSpiceDbGuard.Input input=capture(candidate(AuthorityMatchMode.ALL_OF,1),Set.of(first,second));
        assertThrows(IllegalStateException.class,()->transactions.executeWithoutResult(status->guard.check(input,clock.instant().plusSeconds(60))));
        assertThrows(IllegalStateException.class,()->guard.capture(account,group,input.candidate(),Set.of(first)));
        verifyNoInteractions(graph);
    }

    /** Cohort omission is inert, while enabled incomplete configuration cannot start. */
    @Test void cohortConfigurationIsIndependentAndBounded() {
        assertFalse(guard.applies(UUID.randomUUID()));
        DefaultListableBeanFactory beans=new DefaultListableBeanFactory();
        assertThrows(IllegalStateException.class,()->new IndividualSpiceDbGuard(jdbc,clock,beans.getBeanProvider(SpiceDbPermissionClient.class),
                new MockEnvironment().withProperty("auth.spicedb.individual.enabled","true"),new SimpleMeterRegistry()));
    }

    /** @param policy current policy @param local exact local grants @return committed source evidence */
    private IndividualSpiceDbGuard.Input capture(OperationPolicyCandidate policy,Set<UUID> local) {
        return transactions.execute(status->guard.capture(account,group,policy,local));
    }
    /** @param mode required matching mode @param revision current global fence @return stable catalog dependencies */
    private OperationPolicyCandidate candidate(AuthorityMatchMode mode,long revision) {
        OperationPolicySnapshot snapshot=new OperationPolicySnapshot(new UUID(1,1),"document-service","file.read",1,
                new UUID(1,2),1,"INDIVIDUAL",1,new UUID(1,3),1,new OperationAuthorityPolicy(Set.of(first,second),mode,true),
                Set.of(first,second),Map.of(first,1L,second,1L));
        return new OperationPolicyCandidate(snapshot,revision,Map.of(first,"one",second,"two"),Set.of(first,second));
    }
    /** @param allowed graph result @param revision pinned revision @return complete response */
    private static CheckPermissionResponse answer(boolean allowed,String revision) {
        return CheckPermissionResponse.newBuilder().setCheckedAt(ZedToken.newBuilder().setToken(revision))
                .setPermissionship(allowed?CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION:
                        CheckPermissionResponse.Permissionship.PERMISSIONSHIP_NO_PERMISSION).build();
    }
    /** @param code expected HTTP status @param action protected action */
    private static void assertFailure(int code,Runnable action) { assertEquals(code,assertThrows(OperationAuthorizationFailure.class,action::run).status().value()); }
    private static final class IntentJdbc extends JdbcTemplate {
        private boolean applied=true;
        @Override public int update(String sql,Object... args) { return 1; }
        @Override @SuppressWarnings("unchecked") public <T> List<T> query(String sql,RowMapper<T> mapper,Object... args) {
            if(sql.contains("zed_token")) return applied?(List<T>)List.of("committed"):List.of();
            throw new AssertionError("Unexpected query");
        }
    }
    private static final class MutableClock extends Clock {
        private Instant now=Instant.parse("2026-11-01T12:00:00Z");
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
    private static final class LocalTransactions extends AbstractPlatformTransactionManager {
        @Override protected Object doGetTransaction() { return new Object(); }
        @Override protected void doBegin(Object transaction,TransactionDefinition definition) { }
        @Override protected void doCommit(DefaultTransactionStatus status) { }
        @Override protected void doRollback(DefaultTransactionStatus status) { }
    }
}
