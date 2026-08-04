package com.unidocs.auth.authorization.application;

import com.authzed.api.v1.CheckPermissionRequest;
import com.authzed.api.v1.CheckPermissionResponse;
import com.authzed.api.v1.ZedToken;
import com.unidocs.auth.authorization.domain.AuthorityMatchMode;
import com.unidocs.auth.authorization.api.OperationAuthorizationResponse;
import com.unidocs.auth.authorization.domain.OperationAuthorityPolicy;
import com.unidocs.auth.authorization.domain.OperationPolicySnapshot;
import com.unidocs.auth.authorization.domain.RegisteredOperation;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import com.unidocs.auth.security.spicedb.SpiceDbPermissionClient;
import com.unidocs.auth.session.application.SessionAccess;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.grpc.Status;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.never;

class ProfessionalSpiceDbCanaryTests {
    /**
     * Preserves professional local-group aliases while rejecting student scope types at final revalidation.
     * @param type current owning group type
     * @param eligible whether this type belongs to the professional team scope
     */
    @ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"TEAM,true","PROJECT,true","CUSTOM,true","COURSE,false","CLASS,false"})
    void localGroupScopeRevalidationUsesProfessionalTeamContract(String type,boolean eligible) {
        UUID group=UUID.randomUUID();
        ProfessionalSpiceDbCanary.Fence fence=new ProfessionalSpiceDbCanary.Fence(10,5,"token",null);
        JdbcTemplate jdbc=new JdbcTemplate() {
            /** {@inheritDoc} */
            @SuppressWarnings("unchecked")
            @Override public <T> java.util.List<T> query(String sql,org.springframework.jdbc.core.RowMapper<T> mapper,Object... args) {
                if(sql.contains("FROM spicedb_organization_sync_state"))return (java.util.List<T>)java.util.List.of(fence);
                if(sql.contains("SELECT type FROM iam_group"))return (java.util.List<T>)java.util.List.of(type);
                throw new AssertionError("Unexpected scope revalidation query");
            }
        };
        ProfessionalAuthorizationService professional=mock(ProfessionalAuthorizationService.class);
        ProfessionalSpiceDbCanary enforcing=new ProfessionalSpiceDbCanary(ORGANIZATION.toString(),false,true,true,
                mock(SessionAccess.class),professional,mock(OperationPolicyCatalogRepository.class),client,jdbc,
                Clock.systemUTC(),new SimpleMeterRegistry());
        OperationAuthorizationResponse response=new OperationAuthorizationResponse(ACCOUNT,UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),
                "team.access.update","ORGANIZATION",UUID.randomUUID(),AuthorityMatchMode.ANY_OF,Set.of("team.access.update"),
                Set.of("team.access.update"),1,1,1,1,1,Map.of(A,1L),java.time.Instant.EPOCH,java.time.Instant.EPOCH,"ALLOWED");
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        ProfessionalSpiceDbCanary.Decision decision=new ProfessionalSpiceDbCanary.Decision(response,fence,ORGANIZATION,
                "team.access.update",group,"team",Set.of(A),true,null,null,Set.of(group),Set.of(),"snapshot");
        when(professional.requireGraph(context,ACCOUNT,ORGANIZATION,group,"auth-service","team.access.update",Set.of(A))).thenReturn(response);
        when(professional.ancestors(ORGANIZATION,group)).thenReturn(Set.of(group));
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            if(eligible) {
                assertEquals(response,enforcing.revalidate(decision,context,ACCOUNT,ORGANIZATION));
                verify(professional).guardTransactionCompletion(context,ACCOUNT,null);
            } else assertThrows(OperationAuthorizationFailure.class,()->enforcing.revalidate(decision,context,ACCOUNT,ORGANIZATION));
            verify(professional,never()).require(any(),any(),any(),any(),any(),any());
        } finally { TransactionSynchronizationManager.setActualTransactionActive(false); }
    }
    /**
     * Rejects graph evidence that expires while the final recipient lock is acquired.
     * @param secondsAfterBoundary lock acquisition offset from the scheduled transition
     */
    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(longs = {-1, 0, 1})
    void scopeLockWaitCannotExtendProjectionExpiry(long secondsAfterBoundary) {
        java.time.Instant started = java.time.Instant.parse("2026-10-31T12:00:00Z");
        java.time.Instant boundary = started.plusSeconds(60);
        java.util.concurrent.atomic.AtomicReference<java.time.Instant> time =
                new java.util.concurrent.atomic.AtomicReference<>(started);
        Clock clock = mock(Clock.class);
        when(clock.instant()).thenAnswer(call -> time.get());
        UUID recipient = UUID.randomUUID(), membership = UUID.randomUUID();
        ProfessionalSpiceDbCanary.Fence fence = new ProfessionalSpiceDbCanary.Fence(10, 5, "token", boundary);
        JdbcTemplate jdbc = new JdbcTemplate() {
            /** Simulates a recipient row lock acquired after the projection expiry check. */
            @SuppressWarnings("unchecked")
            @Override public <T> java.util.List<T> query(String sql, org.springframework.jdbc.core.RowMapper<T> mapper,
                    Object... args) {
                if (sql.contains("FROM spicedb_organization_sync_state")) return (java.util.List<T>) java.util.List.of(fence);
                if (sql.contains("SELECT m.id FROM organization_membership")) {
                    time.set(boundary.plusSeconds(secondsAfterBoundary));
                    return (java.util.List<T>) java.util.List.of(membership);
                }
                throw new AssertionError("Unexpected authorization query");
            }
        };
        ProfessionalAuthorizationService professional = mock(ProfessionalAuthorizationService.class);
        ProfessionalSpiceDbCanary enforcing = new ProfessionalSpiceDbCanary(ORGANIZATION.toString(), false, true, true,
                mock(SessionAccess.class), professional, mock(OperationPolicyCatalogRepository.class), client, jdbc,
                clock, new SimpleMeterRegistry());
        SessionAccess.Context context = mock(SessionAccess.Context.class);
        OperationAuthorizationResponse response = new OperationAuthorizationResponse(ACCOUNT, UUID.randomUUID(),
                UUID.randomUUID(), UUID.randomUUID(), "organization.group.assign", "ORGANIZATION", UUID.randomUUID(),
                AuthorityMatchMode.ANY_OF, Set.of("group.assign"), Set.of("group.assign"), 1, 1, 1, 1, 1,
                Map.of(A, 1L), started, started, "ALLOWED");
        ProfessionalSpiceDbCanary.Decision decision = new ProfessionalSpiceDbCanary.Decision(response, fence,
                ORGANIZATION, "organization.group.assign", null, "organization", Set.of(A), true, recipient,
                membership, Set.of(), Set.of(), "snapshot",
                new ProfessionalSpiceDbCanary.RecipientScopeProof(ORGANIZATION, Set.of(A), membership));
        when(professional.requireGraph(context, ACCOUNT, ORGANIZATION, null, "auth-service",
                "organization.group.assign", Set.of(A))).thenReturn(response);
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            if (secondsAfterBoundary < 0) {
                assertEquals(response, enforcing.revalidate(decision, context, ACCOUNT, ORGANIZATION));
            } else {
                assertEquals(HttpStatus.SERVICE_UNAVAILABLE, assertThrows(OperationAuthorizationFailure.class,
                        () -> enforcing.revalidate(decision, context, ACCOUNT, ORGANIZATION)).status());
            }
            verify(professional, never()).require(any(), any(), any(), any(), any(), any());
        } finally {
            TransactionSynchronizationManager.setActualTransactionActive(false);
        }
    }

    @Test
    void graphDecisionCannotBeReusedForAnotherOrganization() {
        ProfessionalAuthorizationService professional=mock(ProfessionalAuthorizationService.class);
        ProfessionalSpiceDbCanary enforcing=new ProfessionalSpiceDbCanary(ORGANIZATION.toString(),false,true,true,
                mock(SessionAccess.class),professional,mock(OperationPolicyCatalogRepository.class),client,
                mock(JdbcTemplate.class),Clock.systemUTC(),new SimpleMeterRegistry());
        ProfessionalSpiceDbCanary.Decision other=new ProfessionalSpiceDbCanary.Decision(
                mock(OperationAuthorizationResponse.class),null,UUID.randomUUID(),"organization.group.create",null,
                "organization",Set.of(A),true,null,null,Set.of(),Set.of(),"snapshot");
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE,assertThrows(OperationAuthorizationFailure.class,
                ()->enforcing.requireDecision(ORGANIZATION,null,"organization.group.create",other)).status());
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            assertEquals(HttpStatus.SERVICE_UNAVAILABLE,assertThrows(OperationAuthorizationFailure.class,
                    ()->enforcing.revalidate(other,mock(SessionAccess.Context.class),ACCOUNT,ORGANIZATION)).status());
            verifyNoInteractions(professional);
        } finally {
            TransactionSynchronizationManager.setActualTransactionActive(false);
        }
    }

    private enum ChangedBeforeCommit { NONE, POLICY, PROJECTION, SCOPE_TYPE, ANCESTOR, RECIPIENT,
        ACTOR_MEMBERSHIP, ACTOR_DEPARTMENT, RECIPIENT_DEPARTMENT }

    /**
     * Revalidates the exact graph-proved department and both member identities before allowing assignment.
     * @param changed dependency changed after graph preflight, or NONE for an unchanged proof
     */
    @ParameterizedTest
    @EnumSource(ChangedBeforeCommit.class)
    void assignmentScopeProofRequiresCurrentActorAndRecipient(ChangedBeforeCommit changed) {
        UUID group=UUID.randomUUID(),recipient=UUID.randomUUID(),membership=UUID.randomUUID();
        UUID department=UUID.randomUUID(),actorMembership=UUID.randomUUID();
        UUID session=UUID.randomUUID(),user=UUID.randomUUID(),operationId=UUID.randomUUID(),policyId=UUID.randomUUID();
        String operation="organization.group.assign";
        ProfessionalAuthorizationService professional=mock(ProfessionalAuthorizationService.class);
        ProfessionalSpiceDbCanary.Fence fence=new ProfessionalSpiceDbCanary.Fence(10,5,"token",null);
        JdbcTemplate jdbc=new JdbcTemplate() {
            @SuppressWarnings("unchecked")
            @Override public <T> java.util.List<T> query(String sql, org.springframework.jdbc.core.RowMapper<T> mapper,
                    Object... args) {
                if(sql.contains("FROM spicedb_organization_sync_state"))
                    return (java.util.List<T>)java.util.List.of(changed==ChangedBeforeCommit.PROJECTION
                            ? new ProfessionalSpiceDbCanary.Fence(11,5,"token",null):fence);
                if(sql.contains("SELECT type FROM iam_group")) {
                    boolean target=java.util.Arrays.equals((byte[])args[1],com.unidocs.auth.session.persistence.SessionRepository.bytes(group));
                    return (java.util.List<T>)java.util.List.of(!target || changed==ChangedBeforeCommit.SCOPE_TYPE?"DEPARTMENT":"TEAM");
                }
                if(sql.contains("SELECT m.id FROM organization_membership")) {
                    boolean actor=java.util.Arrays.equals((byte[])args[1],com.unidocs.auth.session.persistence.SessionRepository.bytes(ACCOUNT));
                    UUID current=actor?actorMembership:membership;
                    if(actor && changed==ChangedBeforeCommit.ACTOR_MEMBERSHIP
                            || !actor && changed==ChangedBeforeCommit.RECIPIENT) current=UUID.randomUUID();
                    return (java.util.List<T>)java.util.List.of(current);
                }
                if(sql.contains("SELECT gm.id FROM group_membership")) {
                    boolean actor=java.util.Arrays.equals((byte[])args[2],com.unidocs.auth.session.persistence.SessionRepository.bytes(ACCOUNT));
                    return actor && changed==ChangedBeforeCommit.ACTOR_DEPARTMENT
                            || !actor && changed==ChangedBeforeCommit.RECIPIENT_DEPARTMENT
                            ? java.util.List.of():(java.util.List<T>)java.util.List.of(UUID.randomUUID());
                }
                throw new AssertionError("Unexpected authorization query");
            }
        };
        ProfessionalSpiceDbCanary enforcing=new ProfessionalSpiceDbCanary(ORGANIZATION.toString(),false,true,true,
                mock(SessionAccess.class),professional,mock(OperationPolicyCatalogRepository.class),client,jdbc,
                Clock.systemUTC(),new SimpleMeterRegistry());
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        OperationAuthorizationResponse before=new OperationAuthorizationResponse(ACCOUNT,user,session,operationId,
                operation,"ORGANIZATION",policyId,AuthorityMatchMode.ANY_OF,Set.of("group.assign"),
                Set.of("group.assign"),1,1,1,1,1,Map.of(A,1L),java.time.Instant.EPOCH,
                java.time.Instant.EPOCH,"ALLOWED");
        OperationAuthorizationResponse current=changed==ChangedBeforeCommit.POLICY
                ? new OperationAuthorizationResponse(ACCOUNT,user,session,operationId,operation,"ORGANIZATION",
                        policyId,AuthorityMatchMode.ANY_OF,Set.of("group.assign"),Set.of("group.assign"),
                        1,2,1,1,1,Map.of(A,1L),java.time.Instant.EPOCH,java.time.Instant.EPOCH,"ALLOWED")
                : before;
        ProfessionalSpiceDbCanary.Decision decision=new ProfessionalSpiceDbCanary.Decision(before,fence,ORGANIZATION,operation,
                group,"team",Set.of(A),true,recipient,membership,Set.of(group,department),Set.of(department),"snapshot",
                new ProfessionalSpiceDbCanary.RecipientScopeProof(department,Set.of(A),actorMembership));
        when(professional.requireGraph(context,ACCOUNT,ORGANIZATION,group,"auth-service",operation,Set.of(A)))
                .thenReturn(current);
        when(professional.ancestors(ORGANIZATION,group)).thenReturn(changed==ChangedBeforeCommit.ANCESTOR
                ? Set.of(group,UUID.randomUUID()):Set.of(group,department));
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            if(changed==ChangedBeforeCommit.NONE) {
                assertEquals(before,enforcing.revalidate(decision,context,ACCOUNT,ORGANIZATION));
                assertDoesNotThrow(()->enforcing.requireAssignmentRecipient(decision,recipient));
                assertEquals(HttpStatus.SERVICE_UNAVAILABLE,assertThrows(OperationAuthorizationFailure.class,
                        ()->enforcing.requireAssignmentRecipient(decision,UUID.randomUUID())).status());
            } else {
                OperationAuthorizationFailure failure=assertThrows(OperationAuthorizationFailure.class,
                        ()->enforcing.revalidate(decision,context,ACCOUNT,ORGANIZATION));
                assertEquals(changed==ChangedBeforeCommit.ACTOR_DEPARTMENT || changed==ChangedBeforeCommit.RECIPIENT_DEPARTMENT
                        ? HttpStatus.FORBIDDEN:HttpStatus.SERVICE_UNAVAILABLE,failure.status());
            }
            verify(professional,never()).require(context,ACCOUNT,ORGANIZATION,group,"auth-service",operation);
        } finally {
            TransactionSynchronizationManager.setActualTransactionActive(false);
        }
    }

    private static final UUID ORGANIZATION = UUID.fromString("00000000-0000-0000-0000-000000000010");
    private static final UUID ACCOUNT = UUID.fromString("00000000-0000-0000-0000-000000000011");
    private static final UUID A = UUID.fromString("00000000-0000-0000-0000-000000000012");
    private static final UUID B = UUID.fromString("00000000-0000-0000-0000-000000000013");
    private final SpiceDbPermissionClient client = mock(SpiceDbPermissionClient.class);
    private final ProfessionalSpiceDbCanary canary = new ProfessionalSpiceDbCanary(ORGANIZATION.toString(),
            mock(SessionAccess.class), mock(ProfessionalAuthorizationService.class),
            mock(OperationPolicyCatalogRepository.class), client, mock(JdbcTemplate.class), Clock.systemUTC(),
            new SimpleMeterRegistry());

    @Test
    void employeeCreateRequiresItsSeparateServerOwnedSwitch() {
        assertTrue(canary.applies(ORGANIZATION, "organization.group.create"));
        assertEquals(false, canary.applies(ORGANIZATION, "organization.employee.create"));
        ProfessionalSpiceDbCanary enabled = new ProfessionalSpiceDbCanary(ORGANIZATION.toString(), true, false,
                mock(SessionAccess.class), mock(ProfessionalAuthorizationService.class),
                mock(OperationPolicyCatalogRepository.class), client, mock(JdbcTemplate.class), Clock.systemUTC(),
                new SimpleMeterRegistry());
        assertTrue(enabled.applies(ORGANIZATION, "organization.employee.create"));
        assertEquals(false, enabled.applies(UUID.randomUUID(), "organization.employee.create"));
        assertEquals(false, enabled.applies(ORGANIZATION, "organization.employee.reset"));
        ProfessionalSpiceDbCanary management = new ProfessionalSpiceDbCanary(ORGANIZATION.toString(), false, true,
                mock(SessionAccess.class), mock(ProfessionalAuthorizationService.class),
                mock(OperationPolicyCatalogRepository.class), client, mock(JdbcTemplate.class), Clock.systemUTC(),
                new SimpleMeterRegistry());
        assertTrue(management.applies(ORGANIZATION, "organization.employee.reset"));
        assertTrue(management.applies(ORGANIZATION, "team.access.update"));
        assertEquals(false, management.applies(ORGANIZATION, "file.read"));
    }

    @Test
    void managementSwitchCoversEveryRegisteredProfessionalManagementOperation() {
        ProfessionalSpiceDbCanary management = new ProfessionalSpiceDbCanary(ORGANIZATION.toString(), false, true,
                mock(SessionAccess.class), mock(ProfessionalAuthorizationService.class),
                mock(OperationPolicyCatalogRepository.class), client, mock(JdbcTemplate.class), Clock.systemUTC(),
                new SimpleMeterRegistry());
        OperationRegistry registry = new OperationRegistry();
        for (Map.Entry<String, RegisteredOperation> entry : registry.definitions().entrySet()) {
            String operation = entry.getKey();
            if (!entry.getValue().serviceId().equals("auth-service")) continue;
            if (operation.startsWith("organization.") || operation.equals("department.access.update")
                    || operation.equals("team.access.update")) {
                assertTrue(management.applies(ORGANIZATION, operation), operation);
            }
        }
        assertEquals(false, management.applies(ORGANIZATION, "student.admission.review"));
        assertEquals(false, management.applies(UUID.randomUUID(), "organization.group.create"));
    }

    @Test
    void graphEnforcementRequiresTheExplicitManagementSwitch() {
        assertThrows(IllegalArgumentException.class,()->new ProfessionalSpiceDbCanary(ORGANIZATION.toString(),
                false,false,true,mock(SessionAccess.class),mock(ProfessionalAuthorizationService.class),
                mock(OperationPolicyCatalogRepository.class),client,mock(JdbcTemplate.class),Clock.systemUTC(),
                new SimpleMeterRegistry()));
    }

    @Test
    void revokedGraphDecisionCannotFallBackToLegacySqlAuthority() {
        ProfessionalAuthorizationService professional=mock(ProfessionalAuthorizationService.class);
        ProfessionalSpiceDbCanary enforcing=new ProfessionalSpiceDbCanary(ORGANIZATION.toString(),false,true,true,
                mock(SessionAccess.class),professional,mock(OperationPolicyCatalogRepository.class),client,
                mock(JdbcTemplate.class),Clock.systemUTC(),new SimpleMeterRegistry());
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        String operation="organization.group.create";
        ProfessionalSpiceDbCanary.Decision decision=new ProfessionalSpiceDbCanary.Decision(
                mock(OperationAuthorizationResponse.class),null,ORGANIZATION,operation,null,"organization",Set.of(A),true,
                null,null,Set.of(),Set.of(),"snapshot-1");
        when(professional.requireGraph(context,ACCOUNT,ORGANIZATION,null,"auth-service",operation,Set.of(A)))
                .thenThrow(new OperationAuthorizationFailure(HttpStatus.FORBIDDEN,"PROFESSIONAL_AUTHORITY_DENIED"));
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            OperationAuthorizationFailure failure=assertThrows(OperationAuthorizationFailure.class,
                    ()->enforcing.revalidate(decision,context,ACCOUNT,ORGANIZATION));
            assertEquals(HttpStatus.FORBIDDEN,failure.status());
            verify(professional,never()).require(context,ACCOUNT,ORGANIZATION,null,"auth-service",operation);
        } finally {
            TransactionSynchronizationManager.setActualTransactionActive(false);
        }
    }

    @Test
    void groupScopeRequiresAnAuthorityAtThatScope() {
        UUID group = UUID.fromString("00000000-0000-0000-0000-000000000014");
        Map<String, Boolean> permissions = Map.of(group.toString().replace("-", "")
                + A.toString().replace("-", "") + ":category_grant", true,
                group.toString().replace("-", "") + A.toString().replace("-", "") + ":scoped_grant", true);
        answer(permissions);
        assertDoesNotThrow(() -> canary.checkGraph(ACCOUNT, ORGANIZATION, group, "team", policy(AuthorityMatchMode.ANY_OF)));
        OperationAuthorizationFailure failure = assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkGraph(ACCOUNT, ORGANIZATION, null, "organization", policy(AuthorityMatchMode.ANY_OF)));
        assertEquals(HttpStatus.FORBIDDEN, failure.status());
    }

    @Test
    void anyOfRequiresTheSameAuthorityAtCategoryAndScope() {
        Map<String, Boolean> permissions = new HashMap<>();
        permissions.put(key(A, "category_grant"), true);
        permissions.put(key(B, "scoped_grant"), true);
        answer(permissions);
        OperationAuthorizationFailure failure = assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkGraph(ACCOUNT, ORGANIZATION, policy(AuthorityMatchMode.ANY_OF)));
        assertEquals(HttpStatus.FORBIDDEN, failure.status());
    }

    @Test
    void anyOfAcceptsOneCommonAuthorityAtOnePinnedSnapshot() {
        Map<String, Boolean> permissions = Map.of(key(B, "category_grant"), true, key(B, "scoped_grant"), true);
        answer(permissions);
        assertEquals(Set.of(B),assertDoesNotThrow(() -> canary.checkGraph(ACCOUNT, ORGANIZATION,
                policy(AuthorityMatchMode.ANY_OF))));
    }

    @Test
    void allOfRejectsMissingAuthority() {
        Map<String, Boolean> permissions = Map.of(key(A, "category_grant"), true, key(A, "scoped_grant"), true);
        answer(permissions);
        OperationAuthorizationFailure failure = assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkGraph(ACCOUNT, ORGANIZATION, policy(AuthorityMatchMode.ALL_OF)));
        assertEquals(HttpStatus.FORBIDDEN, failure.status());
    }

    @Test
    void explicitOperationDenyOverridesMatchingAuthorities() {
        answer(Map.of("explicit_deny:operation", true));
        OperationAuthorizationFailure failure = assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkGraph(ACCOUNT, ORGANIZATION, policy(AuthorityMatchMode.ANY_OF)));
        assertEquals(HttpStatus.FORBIDDEN, failure.status());
    }

    @Test
    void explicitAccountDenyOverridesMatchingAuthorities() {
        answer(Map.of(operationScopeKey(ORGANIZATION), true));
        OperationAuthorizationFailure failure = assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkGraph(ACCOUNT, ORGANIZATION, policy(AuthorityMatchMode.ANY_OF)));
        assertEquals(HttpStatus.FORBIDDEN, failure.status());
    }

    @Test
    void accountRestrictionForAnotherOperationDoesNotDenyThisOperation() {
        UUID anotherOperation = UUID.fromString("00000000-0000-0000-0000-000000000023");
        String unrelatedKey = ORGANIZATION.toString().replace("-", "")
                + anotherOperation.toString().replace("-", "") + ":denied";
        answer(Map.of(unrelatedKey, true, key(B, "category_grant"), true, key(B, "scoped_grant"), true));
        assertEquals(Set.of(B), canary.checkGraph(ACCOUNT, ORGANIZATION, policy(AuthorityMatchMode.ANY_OF)));
    }

    @Test
    void targetGroupAccountRestrictionDeniesOnlyItsOperation() {
        UUID group = UUID.fromString("00000000-0000-0000-0000-000000000014");
        String capability = group.toString().replace("-", "") + A.toString().replace("-", "");
        answer(Map.of(operationScopeKey(group), true, capability + ":category_grant", true,
                capability + ":scoped_grant", true));
        assertEquals(HttpStatus.FORBIDDEN, assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkGraph(ACCOUNT, ORGANIZATION, group, "team",
                        policy(AuthorityMatchMode.ANY_OF))).status());
    }

    @Test
    void inconsistentGraphSnapshotFailsClosed() {
        when(client.checkPermission(any(CheckPermissionRequest.class))).thenAnswer(invocation -> {
            CheckPermissionRequest request = invocation.getArgument(0);
            String token = request.getPermission().equals("member") ? "snapshot-1" : "snapshot-2";
            return CheckPermissionResponse.newBuilder().setCheckedAt(ZedToken.newBuilder().setToken(token))
                    .setPermissionship(CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION).build();
        });
        OperationAuthorizationFailure failure = assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkGraph(ACCOUNT, ORGANIZATION, policy(AuthorityMatchMode.ANY_OF)));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, failure.status());
    }

    @Test
    void dependencyOutageFailsClosed() {
        when(client.checkPermission(any(CheckPermissionRequest.class))).thenThrow(Status.UNAVAILABLE.asRuntimeException());
        OperationAuthorizationFailure failure = assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkGraph(ACCOUNT, ORGANIZATION, policy(AuthorityMatchMode.ANY_OF)));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, failure.status());
    }

    @Test
    void assignmentRejectsGroupGrantWithoutMatchingOrganizationScope() {
        UUID recipient = UUID.fromString("00000000-0000-0000-0000-000000000015");
        answer(Map.of(key(A, "category_grant"), true));
        OperationAuthorizationFailure failure = assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkRecipientGraph(ACCOUNT, recipient, ORGANIZATION, Set.of(),
                        policy(AuthorityMatchMode.ANY_OF), Set.of(A), ZedToken.newBuilder().setToken("snapshot-1").build()));
        assertEquals(HttpStatus.FORBIDDEN, failure.status());
    }

    @Test
    void assignmentAcceptsSameAuthorityAtOrganizationScope() {
        UUID recipient = UUID.fromString("00000000-0000-0000-0000-000000000015");
        answer(Map.of(key(A, "category_grant"), true, key(A, "responsibility_grant"), true));
        assertDoesNotThrow(() -> canary.checkRecipientGraph(ACCOUNT, recipient, ORGANIZATION, Set.of(),
                policy(AuthorityMatchMode.ANY_OF), Set.of(A), ZedToken.newBuilder().setToken("snapshot-1").build()));
    }

    /** Inherited/baseline scoped grants cannot replace a direct professional management responsibility. */
    @Test
    void assignmentRejectsInheritedOrBaselineGrantWithoutDirectResponsibility() {
        UUID recipient=UUID.randomUUID();
        answer(Map.of(key(A,"category_grant"),true,key(A,"scoped_grant"),true));
        assertEquals(HttpStatus.FORBIDDEN,assertThrows(OperationAuthorizationFailure.class,
                ()->canary.checkRecipientGraph(ACCOUNT,recipient,ORGANIZATION,Set.of(),policy(AuthorityMatchMode.ANY_OF),
                        Set.of(A),ZedToken.newBuilder().setToken("snapshot-1").build())).status());
    }

    /** ALL_OF cannot borrow an organization responsibility to complete a department's partial witness. */
    @Test
    void assignmentRejectsInheritedSplitAllOfEvenWhenTargetScopeHasBothInheritedGrants() {
        UUID department=UUID.randomUUID(),recipient=UUID.randomUUID();
        String prefix=department.toString().replace("-","");
        answer(Map.of(key(A,"category_grant"),true,key(A,"responsibility_grant"),true,
                prefix+A.toString().replace("-","")+":category_grant",true,
                prefix+B.toString().replace("-","")+":category_grant",true,
                prefix+A.toString().replace("-","")+":scoped_grant",true,
                prefix+B.toString().replace("-","")+":scoped_grant",true,
                prefix+B.toString().replace("-","")+":responsibility_grant",true));
        assertEquals(HttpStatus.FORBIDDEN,assertThrows(OperationAuthorizationFailure.class,
                ()->canary.checkRecipientGraph(ACCOUNT,recipient,ORGANIZATION,Set.of(department),policy(AuthorityMatchMode.ALL_OF),
                        Set.of(A,B),ZedToken.newBuilder().setToken("snapshot-1").build())).status());
    }

    @Test
    void assignmentAcceptsEligibleDepartmentScope() {
        UUID department = UUID.fromString("00000000-0000-0000-0000-000000000016");
        UUID recipient = UUID.fromString("00000000-0000-0000-0000-000000000015");
        answerDepartment(department, recipient, true, true, true);
        assertDoesNotThrow(() -> canary.checkRecipientGraph(ACCOUNT, recipient, ORGANIZATION, Set.of(department),
                policy(AuthorityMatchMode.ANY_OF), Set.of(A), ZedToken.newBuilder().setToken("snapshot-1").build()));
    }

    @Test
    void assignmentRejectsRecipientOutsideManagedDepartment() {
        UUID department = UUID.fromString("00000000-0000-0000-0000-000000000016");
        UUID recipient = UUID.fromString("00000000-0000-0000-0000-000000000015");
        answerDepartment(department, recipient, false, true, true);
        OperationAuthorizationFailure failure = assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkRecipientGraph(ACCOUNT, recipient, ORGANIZATION, Set.of(department),
                        policy(AuthorityMatchMode.ANY_OF), Set.of(A), ZedToken.newBuilder().setToken("snapshot-1").build()));
        assertEquals(HttpStatus.FORBIDDEN, failure.status());
    }

    @Test
    void assignmentRejectsSplitDepartmentAuthorityAndIncompleteAllOf() {
        UUID department = UUID.fromString("00000000-0000-0000-0000-000000000016");
        UUID recipient = UUID.fromString("00000000-0000-0000-0000-000000000015");
        ZedToken snapshot = ZedToken.newBuilder().setToken("snapshot-1").build();
        answerDepartment(department, recipient, true, true, false);
        assertEquals(HttpStatus.FORBIDDEN, assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkRecipientGraph(ACCOUNT, recipient, ORGANIZATION, Set.of(department),
                        policy(AuthorityMatchMode.ANY_OF), Set.of(A, B), snapshot)).status());
        answerDepartment(department, recipient, true, true, true);
        assertEquals(HttpStatus.FORBIDDEN, assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkRecipientGraph(ACCOUNT, recipient, ORGANIZATION, Set.of(department),
                        policy(AuthorityMatchMode.ALL_OF), Set.of(A, B), snapshot)).status());
    }

    @Test
    void assignmentScopeGraphOutageFailsClosed() {
        UUID recipient = UUID.fromString("00000000-0000-0000-0000-000000000015");
        when(client.checkPermission(any(CheckPermissionRequest.class))).thenThrow(Status.UNAVAILABLE.asRuntimeException());
        OperationAuthorizationFailure failure = assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkRecipientGraph(ACCOUNT, recipient, ORGANIZATION, Set.of(),
                        policy(AuthorityMatchMode.ANY_OF), Set.of(A),
                        ZedToken.newBuilder().setToken("snapshot-1").build()));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, failure.status());
    }

    private void answerDepartment(UUID department, UUID recipient, boolean recipientMember,
            boolean categoryA, boolean scopedA) {
        when(client.checkPermission(any(CheckPermissionRequest.class))).thenAnswer(invocation -> {
            CheckPermissionRequest request = invocation.getArgument(0);
            assertEquals("snapshot-1", request.getConsistency().getAtExactSnapshot().getToken());
            String resource = request.getResource().getObjectId();
            String subject = request.getSubject().getObject().getObjectId();
            boolean allowed = request.getPermission().equals("member")
                    ? resource.equals(ORGANIZATION.toString()) && subject.equals(recipient.toString())
                    || resource.equals(department.toString()) && (!subject.equals(recipient.toString()) || recipientMember)
                    : resource.equals(department.toString().replace("-", "") + A.toString().replace("-", ""))
                    && (request.getPermission().equals("category_grant") && categoryA
                    || request.getPermission().equals("responsibility_grant") && scopedA)
                    || resource.equals(department.toString().replace("-", "") + B.toString().replace("-", ""))
                    && request.getPermission().equals("responsibility_grant") && !scopedA;
            return CheckPermissionResponse.newBuilder().setCheckedAt(ZedToken.newBuilder().setToken("snapshot-1"))
                    .setPermissionship(allowed ? CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION
                            : CheckPermissionResponse.Permissionship.PERMISSIONSHIP_NO_PERMISSION).build();
        });
    }

    private void answer(Map<String, Boolean> permissions) {
        when(client.checkPermission(any(CheckPermissionRequest.class))).thenAnswer(invocation -> {
            CheckPermissionRequest request = invocation.getArgument(0);
            if (request.getPermission().equals("member")
                    && request.getSubject().getObject().getObjectId().equals(ACCOUNT.toString())
                    && request.getResource().getObjectType().equals("organization")) {
                assertTrue(request.getConsistency().getFullyConsistent());
            } else {
                assertEquals("snapshot-1", request.getConsistency().getAtExactSnapshot().getToken());
            }
            String key = request.getPermission().equals("explicit_deny")
                    ? "explicit_deny:" + request.getSubject().getObject().getObjectType()
                    : request.getResource().getObjectId() + ":" + request.getPermission();
            boolean allowed = request.getPermission().equals("member") || permissions.getOrDefault(key, false);
            return CheckPermissionResponse.newBuilder().setCheckedAt(ZedToken.newBuilder().setToken("snapshot-1"))
                    .setPermissionship(allowed ? CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION
                            : CheckPermissionResponse.Permissionship.PERMISSIONSHIP_NO_PERMISSION).build();
        });
    }

    private static String key(UUID authority, String permission) {
        return ORGANIZATION.toString().replace("-", "") + authority.toString().replace("-", "") + ":" + permission;
    }

    private static String operationScopeKey(UUID scope) {
        UUID operation = UUID.fromString("00000000-0000-0000-0000-000000000020");
        return scope.toString().replace("-", "") + operation.toString().replace("-", "") + ":denied";
    }

    private static OperationPolicySnapshot policy(AuthorityMatchMode mode) {
        UUID operation = UUID.fromString("00000000-0000-0000-0000-000000000020");
        UUID policy = UUID.fromString("00000000-0000-0000-0000-000000000021");
        UUID role = UUID.fromString("00000000-0000-0000-0000-000000000022");
        return new OperationPolicySnapshot(operation, "auth-service", "organization.group.create", 1,
                policy, 1, "ORGANIZATION", 1, role, 1,
                new OperationAuthorityPolicy(Set.of(A, B), mode, true), Set.of(A, B), Map.of(A, 1L, B, 1L));
    }
}
