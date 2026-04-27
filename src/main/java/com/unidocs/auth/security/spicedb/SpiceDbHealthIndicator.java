package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.CheckPermissionRequest;
import com.authzed.api.v1.CheckPermissionResponse;
import com.authzed.api.v1.Consistency;
import com.authzed.api.v1.ObjectReference;
import com.authzed.api.v1.SubjectReference;
import io.grpc.StatusRuntimeException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

/** Probes the actual permission path before canary traffic; this result never supplies authorization evidence. */
@Component
public final class SpiceDbHealthIndicator implements HealthIndicator {
    private static final String PROBE_ID = "00000000-0000-0000-0000-000000000000";
    private final boolean canaryEnabled;
    private final SpiceDbPermissionClient client;

    /**
     * Configures dependency readiness only for deployments using organization canaries.
     * @param canaryEnabled whether permission traffic is selected
     * @param clients optional configured permission client
     */
    public SpiceDbHealthIndicator(@Value("${auth.spicedb.canary.enabled:false}") boolean canaryEnabled,
            ObjectProvider<SpiceDbPermissionClient> clients) {
        this.canaryEnabled = canaryEnabled;
        this.client = clients.getIfAvailable();
    }

    /**
     * Performs one deadline-bounded fully consistent read outside application transactions.
     * @return readiness without credentials, graph tokens or exception descriptions
     */
    @Override
    public Health health() {
        if (!canaryEnabled) return Health.up().build();
        if (client == null) return Health.down().withDetail("code", "CLIENT_MISSING").build();
        try {
            CheckPermissionResponse response = client.checkPermission(CheckPermissionRequest.newBuilder()
                    .setConsistency(Consistency.newBuilder().setFullyConsistent(true))
                    .setResource(ObjectReference.newBuilder().setObjectType("organization").setObjectId(PROBE_ID))
                    .setPermission("member").setSubject(SubjectReference.newBuilder().setObject(
                            ObjectReference.newBuilder().setObjectType("account").setObjectId(PROBE_ID))).build());
            if (!response.hasCheckedAt() || response.getCheckedAt().getToken().isBlank()
                    || response.getPermissionship() != CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION
                    && response.getPermissionship() != CheckPermissionResponse.Permissionship.PERMISSIONSHIP_NO_PERMISSION)
                return Health.down().withDetail("code", "INVALID_RESPONSE").build();
            return Health.up().build();
        } catch (StatusRuntimeException failure) {
            return Health.down().withDetail("code", failure.getStatus().getCode().name()).build();
        } catch (RuntimeException failure) {
            return Health.down().withDetail("code", "CLIENT_FAILURE").build();
        }
    }
}
