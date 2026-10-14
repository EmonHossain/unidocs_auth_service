package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.CheckPermissionRequest;
import com.authzed.api.v1.CheckPermissionResponse;
import com.authzed.api.v1.ZedToken;
import io.grpc.Status;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.health.contributor.Health;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class SpiceDbHealthIndicatorTests {
    private final SpiceDbPermissionClient client = mock(SpiceDbPermissionClient.class);

    /** Keeps disabled canaries independent of SpiceDB availability. */
    @Test
    void disabledCanaryDoesNotProbeDependency() {
        assertEquals(org.springframework.boot.health.contributor.Status.UP, indicator(false, client).health().getStatus());
        verifyNoInteractions(client);
    }

    /** Prevents readiness when selected graph traffic has no configured client. */
    @Test
    void enabledCanaryCannotBeReadyWithoutClient() {
        assertEquals(org.springframework.boot.health.contributor.Status.DOWN, indicator(true, null).health().getStatus());
    }

    /**
     * Accepts either definitive permission answer without exposing its revision.
     * @param permission definitive result of the fixed synthetic probe
     */
    @ParameterizedTest
    @EnumSource(value = CheckPermissionResponse.Permissionship.class,
            names = {"PERMISSIONSHIP_HAS_PERMISSION", "PERMISSIONSHIP_NO_PERMISSION"})
    void readyRequiresACompletedFullyConsistentPermissionRead(CheckPermissionResponse.Permissionship permission) {
        when(client.checkPermission(any())).thenAnswer(call -> {
            CheckPermissionRequest request = call.getArgument(0);
            assertTrue(request.getConsistency().getFullyConsistent());
            assertEquals("organization", request.getResource().getObjectType());
            assertEquals("account", request.getSubject().getObject().getObjectType());
            assertEquals("member", request.getPermission());
            return CheckPermissionResponse.newBuilder().setCheckedAt(ZedToken.newBuilder().setToken("private-revision"))
                    .setPermissionship(permission).build();
        });
        Health health = indicator(true, client).health();
        assertEquals(org.springframework.boot.health.contributor.Status.UP, health.getStatus());
        assertTrue(health.getDetails().isEmpty());
    }

    /**
     * Fails readiness on transport/authentication failures with redacted diagnostics.
     * @param code gRPC failure category
     */
    @ParameterizedTest
    @EnumSource(value = Status.Code.class, names = {"DEADLINE_EXCEEDED", "UNAVAILABLE", "UNAUTHENTICATED", "PERMISSION_DENIED"})
    void dependencyFailurePreventsReadinessWithoutExposingDescriptions(Status.Code code) {
        when(client.checkPermission(any())).thenThrow(code.toStatus().withDescription("sensitive-description").asRuntimeException());
        Health health = indicator(true, client).health();
        assertEquals(org.springframework.boot.health.contributor.Status.DOWN, health.getStatus());
        assertEquals(java.util.Map.of("code", code.name()), health.getDetails());
        assertFalse(health.toString().contains("sensitive-description"));
    }

    /** Rejects incomplete and conditional responses rather than declaring the dependency usable. */
    @Test
    void emptyOrConditionalEvidenceCannotDeclareReadiness() {
        when(client.checkPermission(any())).thenReturn(CheckPermissionResponse.getDefaultInstance(),
                CheckPermissionResponse.newBuilder().setCheckedAt(ZedToken.newBuilder().setToken("private-revision"))
                        .setPermissionship(CheckPermissionResponse.Permissionship.PERMISSIONSHIP_CONDITIONAL_PERMISSION).build());
        SpiceDbHealthIndicator indicator = indicator(true, client);
        assertEquals(org.springframework.boot.health.contributor.Status.DOWN, indicator.health().getStatus());
        assertEquals(org.springframework.boot.health.contributor.Status.DOWN, indicator.health().getStatus());
    }

    /**
     * Creates a health probe without starting a Spring context or network connection.
     * @param enabled canary deployment flag
     * @param permissionClient optional configured client
     * @return isolated health indicator
     */
    private SpiceDbHealthIndicator indicator(boolean enabled, SpiceDbPermissionClient permissionClient) {
        @SuppressWarnings("unchecked") ObjectProvider<SpiceDbPermissionClient> clients = mock(ObjectProvider.class);
        when(clients.getIfAvailable()).thenReturn(permissionClient);
        return new SpiceDbHealthIndicator(enabled, clients);
    }
}
