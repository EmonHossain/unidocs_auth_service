package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.PermissionsServiceGrpc;
import com.authzed.api.v1.CheckPermissionRequest;
import com.authzed.api.v1.CheckPermissionResponse;
import java.util.concurrent.TimeUnit;

/** Narrow Java API boundary for permission checks; schema and relationship writes stay out of the request process. */
public final class SpiceDbPermissionClient {
    private final PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions;
    private final long deadlineMillis;

    SpiceDbPermissionClient(PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions, long deadlineMillis) {
        if (permissions == null || deadlineMillis < 1 || deadlineMillis > 10_000) {
            throw new IllegalArgumentException("SpiceDB permission client requires a stub and bounded deadline.");
        }
        this.permissions = permissions;
        this.deadlineMillis = deadlineMillis;
    }

    /**
     * Checks once with a bounded deadline; a transport failure permits only a later fresh request to reconnect.
     * @param request server-constructed permission and consistency contract
     * @return graph response for this request
     * @throws IllegalArgumentException when the request is absent
     * @throws io.grpc.StatusRuntimeException when the dependency cannot complete this check
     */
    public CheckPermissionResponse checkPermission(CheckPermissionRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("A server-constructed SpiceDB check request is required.");
        }
        try {
            return permissions.withDeadlineAfter(deadlineMillis, TimeUnit.MILLISECONDS).checkPermission(request);
        } catch (io.grpc.StatusRuntimeException failure) {
            // A recovered gateway should be reachable on the next fresh request, without retrying this decision.
            if (failure.getStatus().getCode() == io.grpc.Status.Code.UNAVAILABLE
                    && permissions.getChannel() instanceof io.grpc.ManagedChannel channel) channel.resetConnectBackoff();
            throw failure;
        }
    }
}
