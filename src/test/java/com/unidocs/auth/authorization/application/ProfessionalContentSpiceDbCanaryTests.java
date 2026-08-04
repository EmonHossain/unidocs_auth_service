package com.unidocs.auth.authorization.application;

import com.authzed.api.v1.CheckPermissionRequest;
import com.authzed.api.v1.CheckPermissionResponse;
import com.authzed.api.v1.ZedToken;
import com.unidocs.auth.authorization.api.OperationAuthorizationResponse;
import com.unidocs.auth.authorization.domain.AuthorityMatchMode;
import com.unidocs.auth.authorization.domain.OperationAuthorityPolicy;
import com.unidocs.auth.authorization.domain.OperationPolicySnapshot;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import com.unidocs.auth.security.spicedb.SpiceDbPermissionClient;
import com.unidocs.auth.session.application.SessionAccess;
import io.grpc.Status;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Content-specific service, same-authority, exact-sharing and final-fence contracts. */
class ProfessionalContentSpiceDbCanaryTests {
    private final UUID organization = UUID.randomUUID(), account = UUID.randomUUID(), group = UUID.randomUUID();
    private final UUID session = UUID.randomUUID(), user = UUID.randomUUID(), operationId = UUID.randomUUID();
    private final UUID policyId = UUID.randomUUID(), first = UUID.randomUUID(), second = UUID.randomUUID();
    private final Instant now = Instant.parse("2026-11-01T00:00:00Z");
    private final SessionAccess access = mock(SessionAccess.class);
    private final SessionAccess.Context context = mock(SessionAccess.Context.class);
    private final ProfessionalAuthorizationService professional = mock(ProfessionalAuthorizationService.class);
    private final OperationPolicyCatalogRepository policies = mock(OperationPolicyCatalogRepository.class);
    private final SpiceDbPermissionClient graph = mock(SpiceDbPermissionClient.class);
    private final ContentJdbc jdbc = new ContentJdbc();
    private ProfessionalSpiceDbCanary canary;
    private Set<UUID> category = Set.of(), scoped = Set.of();

    /** Keeps management enforcement on to prove it cannot remove the content SQL intersection. */
    @BeforeEach
    void configure() {
        canary = new ProfessionalSpiceDbCanary(organization.toString(), false, true, true, false, true,
                access, professional, policies, graph, jdbc, Clock.fixed(now, ZoneOffset.UTC), new SimpleMeterRegistry());
        when(access.execute(eq(session), eq(account), any())).thenAnswer(call ->
                call.<Function<SessionAccess.Context, Object>>getArgument(2).apply(context));
        when(professional.ancestors(organization, group)).thenReturn(Set.of(group));
        when(graph.checkPermission(any())).thenAnswer(call -> {
            assertFalse(TransactionSynchronizationManager.isActualTransactionActive());
            CheckPermissionRequest request = call.getArgument(0);
            boolean member = request.getPermission().equals("member");
            if (member) assertTrue(request.getConsistency().getFullyConsistent());
            else assertEquals("content-snapshot", request.getConsistency().getAtExactSnapshot().getToken());
            String resource = request.getResource().getObjectId();
            boolean allowed = member || request.getPermission().equals("category_grant")
                    && category.stream().anyMatch(id -> resource.endsWith(compact(id)))
                    || request.getPermission().equals("scoped_grant")
                    && scoped.stream().anyMatch(id -> resource.endsWith(compact(id)));
            return CheckPermissionResponse.newBuilder().setCheckedAt(ZedToken.newBuilder().setToken("content-snapshot"))
                    .setPermissionship(allowed ? CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION
                            : CheckPermissionResponse.Permissionship.PERMISSIONSHIP_NO_PERMISSION).build();
        });
    }

    /**
     * Keeps the content inventory synchronized with registered Document operations.
     * @param operation registered Document operation
     */
    @ParameterizedTest @MethodSource("contentOperations")
    void registeredContentIsSelectedOnlyInItsCohortAndNeverGraphAuthoritative(String operation) {
        assertTrue(canary.applies(organization, operation));
        assertFalse(canary.applies(UUID.randomUUID(), operation));
        assertFalse(canary.enforces(organization, operation));
    }

    /** @return every registered Document operation, excluding Auth-owned management operations */
    private static Stream<String> contentOperations() {
        return new OperationRegistry().definitions().values().stream()
                .filter(operation -> operation.serviceId().equals("document-service"))
                .map(operation -> operation.key());
    }

    /** Disabling both content switches preserves the legacy content path even with management enforcement. */
    @Test void contentRequiresItsOwnSwitch() {
        ProfessionalSpiceDbCanary disabled = new ProfessionalSpiceDbCanary(organization.toString(), false, true, true,
                access, professional, policies, graph, jdbc, Clock.fixed(now, ZoneOffset.UTC), new SimpleMeterRegistry());
        contentOperations().forEach(operation -> assertFalse(disabled.applies(organization, operation)));
        assertFalse(canary.applies(organization, "file.unregistered"));
    }

    /**
     * Uses Document's policy, preserves exact-resource admission and returns the common witness only.
     * @param operation registered content operation
     * @param exact whether an exact-resource relationship replaces group admission
     */
    @ParameterizedTest @CsvSource({"workspace.read,false", "file.read,true", "publication.approve,false"})
    void contentPreflightAndFinalCheckRetainSqlAndIdenticalGraphAuthority(String operation, boolean exact) {
        prepare(operation, exact, AuthorityMatchMode.ANY_OF, Set.of("first", "second"));
        category = Set.of(first, second); scoped = Set.of(second);
        ProfessionalSpiceDbCanary.Decision decision = canary.checkContent(session, account, account, organization, group, operation, exact);
        canary.requireContentDecision(organization, group, operation, exact, decision);
        OperationAuthorizationResponse response = revalidate(decision);
        assertEquals(Set.of("second"), response.categoryAuthorities());
        assertEquals(response.checkedAt(), response.validUntil());
        assertEquals(exact, decision.exactResourceAccess());
        verify(professional).preview(context, account, organization, group, "document-service", operation, exact);
        verify(professional).require(context, account, organization, group, "document-service", operation, exact);
        verify(professional, never()).requireGraph(any(), any(), any(), any(), any(), any(), any());
        verify(professional).guardTransactionCompletion(context, account, null);
    }

    /** Different alternatives at the graph category and scope layers cannot form an ANY_OF witness. */
    @Test void splitGraphAuthorityIsDeniedBeforeFinalSql() {
        prepare("file.read", true, AuthorityMatchMode.ANY_OF, Set.of("first", "second"));
        category = Set.of(first); scoped = Set.of(second);
        assertEquals(HttpStatus.FORBIDDEN, assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkContent(session, account, account, organization, group, "file.read", true)).status());
        verify(professional, never()).require(any(), any(), any(), any(), any(), any(), anyBoolean());
    }

    /** SQL and graph alternatives must also agree before Document receives a witness. */
    @Test void disjointSqlAndGraphWitnessesCannotBeCombinedByDocument() {
        prepare("file.read", true, AuthorityMatchMode.ANY_OF, Set.of("first"));
        category = Set.of(second); scoped = Set.of(second);
        ProfessionalSpiceDbCanary.Decision decision = canary.checkContent(session, account, account, organization, group, "file.read", true);
        assertEquals(HttpStatus.FORBIDDEN, assertThrows(OperationAuthorizationFailure.class, () -> revalidate(decision)).status());
    }

    /** ALL_OF still requires every identical authority in the final SQL/graph intersection. */
    @Test void incompleteAllOfIntersectionIsDenied() {
        prepare("file.read", true, AuthorityMatchMode.ALL_OF, Set.of("first"));
        category = Set.of(first, second); scoped = Set.of(first, second);
        ProfessionalSpiceDbCanary.Decision decision = canary.checkContent(session, account, account, organization, group, "file.read", true);
        assertEquals(HttpStatus.FORBIDDEN, assertThrows(OperationAuthorizationFailure.class, () -> revalidate(decision)).status());
    }

    /** A preflight decision cannot be reused with another exact-resource admission mode. */
    @Test void changedExactAdmissionAndMissingEvidenceFailClosed() {
        prepare("file.read", true, AuthorityMatchMode.ANY_OF, Set.of("first"));
        category = Set.of(first); scoped = Set.of(first);
        ProfessionalSpiceDbCanary.Decision decision = canary.checkContent(session, account, account, organization, group, "file.read", true);
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, assertThrows(OperationAuthorizationFailure.class,
                () -> canary.requireContentDecision(organization, group, "file.read", false, decision)).status());
        assertThrows(OperationAuthorizationFailure.class,
                () -> canary.requireContentDecision(organization, group, "file.read", true, null));
    }

    /** Graph outage cannot fall back to current SQL authority. */
    @Test void graphOutageFailsClosed() {
        prepare("file.read", true, AuthorityMatchMode.ANY_OF, Set.of("first"));
        doThrow(Status.UNAVAILABLE.asRuntimeException()).when(graph).checkPermission(any());
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, assertThrows(OperationAuthorizationFailure.class,
                () -> canary.checkContent(session, account, account, organization, group, "file.read", true)).status());
        verify(professional, never()).require(any(), any(), any(), any(), any(), any(), anyBoolean());
    }

    /** A changed projection floor invalidates previously successful content checks. */
    @Test void changedFinalFenceFailsClosed() {
        prepare("file.read", true, AuthorityMatchMode.ANY_OF, Set.of("first"));
        category = Set.of(first); scoped = Set.of(first);
        ProfessionalSpiceDbCanary.Decision decision = canary.checkContent(session, account, account, organization, group, "file.read", true);
        jdbc.fence = new ProfessionalSpiceDbCanary.Fence(11, 6, "new-token", null);
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, assertThrows(OperationAuthorizationFailure.class, () -> revalidate(decision)).status());
    }

    /** Current IAM denial defeats a successful earlier graph check. */
    @Test void finalRevocationFailsClosed() {
        prepare("file.read", true, AuthorityMatchMode.ANY_OF, Set.of("first"));
        category = Set.of(first); scoped = Set.of(first);
        ProfessionalSpiceDbCanary.Decision decision = canary.checkContent(session, account, account, organization, group, "file.read", true);
        when(professional.require(context, account, organization, group, "document-service", "file.read", true))
                .thenThrow(new OperationAuthorizationFailure(HttpStatus.FORBIDDEN, "REVOKED"));
        assertEquals(HttpStatus.FORBIDDEN, assertThrows(OperationAuthorizationFailure.class, () -> revalidate(decision)).status());
    }

    /**
     * Configures coherent current SQL policy without creating real users or sessions.
     * @param operation registered operation
     * @param exact exact-resource admission
     * @param mode current policy match mode
     * @param sqlAuthorities SQL's matched authority keys
     */
    private void prepare(String operation, boolean exact, AuthorityMatchMode mode, Set<String> sqlAuthorities) {
        OperationAuthorizationResponse response = new OperationAuthorizationResponse(account, user, session, operationId,
                operation, "ORGANIZATION", policyId, mode, Set.of("first", "second"), sqlAuthorities,
                1, 1, 1, 1, 1, Map.of(first, 1L, second, 1L), now, now, "ALLOWED");
        OperationPolicySnapshot policy = new OperationPolicySnapshot(operationId, "document-service", operation, 1,
                policyId, 1, "ORGANIZATION", 1, UUID.randomUUID(), 1,
                new OperationAuthorityPolicy(Set.of(first, second), mode, true), Set.of(first, second), Map.of(first, 1L, second, 1L));
        when(professional.preview(context, account, organization, group, "document-service", operation, exact)).thenReturn(response);
        when(professional.require(context, account, organization, group, "document-service", operation, exact)).thenReturn(response);
        when(policies.findCurrent("document-service", operation, "ORGANIZATION")).thenReturn(Optional.of(policy));
    }

    /**
     * Runs the final check inside the required owning IAM transaction boundary.
     * @param decision earlier graph preflight
     * @return current content intersection
     */
    private OperationAuthorizationResponse revalidate(ProfessionalSpiceDbCanary.Decision decision) {
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try { return canary.revalidate(decision, context, account, organization); }
        finally { TransactionSynchronizationManager.setActualTransactionActive(false); }
    }

    /**
     * Formats the stable authority identifier for graph-object matching.
     * @param id stable authority ID
     * @return graph identifier suffix
     */
    private static String compact(UUID id) { return id.toString().replace("-", ""); }

    private final class ContentJdbc extends JdbcTemplate {
        private ProfessionalSpiceDbCanary.Fence fence = new ProfessionalSpiceDbCanary.Fence(10, 5, "token", null);

        /** {@inheritDoc} */
        @SuppressWarnings("unchecked")
        @Override public <T> List<T> query(String sql, RowMapper<T> mapper, Object... args) {
            if (sql.contains("FROM spicedb_organization_sync_state")) return (List<T>) List.of(fence);
            if (sql.contains("SELECT type FROM iam_group")) return (List<T>) List.of("TEAM");
            throw new AssertionError("Unexpected resource scope query");
        }

        /** {@inheritDoc} */
        @Override public void query(String sql, RowCallbackHandler handler, Object... args) {
            assertTrue(sql.contains("a.status='ACTIVE'"));
            for (Map.Entry<UUID, String> authority : Map.of(first, "first", second, "second").entrySet()) {
                ResultSet row = mock(ResultSet.class);
                try {
                    when(row.getBytes(1)).thenReturn(com.unidocs.auth.session.persistence.SessionRepository.bytes(authority.getKey()));
                    when(row.getString(2)).thenReturn(authority.getValue());
                    handler.processRow(row);
                } catch (SQLException failure) { throw new AssertionError(failure); }
            }
        }
    }
}
