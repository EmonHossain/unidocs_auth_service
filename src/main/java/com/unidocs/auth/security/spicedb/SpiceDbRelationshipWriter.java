package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.PermissionsServiceGrpc;
import com.authzed.api.v1.RelationshipUpdate;
import com.authzed.api.v1.WriteRelationshipsRequest;
import com.authzed.api.v1.WriteRelationshipsResponse;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Narrow idempotent relationship-write API used only by IAM projection workers. */
public final class SpiceDbRelationshipWriter {
    private final PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions;
    private final long deadlineMillis;
    private final int maxBatchSize;

    SpiceDbRelationshipWriter(PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions,
            long deadlineMillis, int maxBatchSize) {
        if (permissions == null || deadlineMillis < 1 || deadlineMillis > 10_000
                || maxBatchSize < 1 || maxBatchSize > 1_000) {
            throw new IllegalArgumentException("SpiceDB relationship writer configuration is invalid.");
        }
        this.permissions = permissions;
        this.deadlineMillis = deadlineMillis;
        this.maxBatchSize = maxBatchSize;
    }

    /**
     * Writes one bounded idempotent batch and requires its exact committed revision.
     * @param updates server-constructed tuple touches or exact deletes
     * @return nonblank committed SpiceDB token
     * @throws IllegalArgumentException when the batch is outside configured bounds
     * @throws IllegalStateException when the gateway response lacks acknowledgement evidence
     */
    public String writeRelationships(List<RelationshipUpdate> updates) {
        if (updates == null || updates.isEmpty() || updates.size() > maxBatchSize) {
            throw new IllegalArgumentException("SpiceDB relationship write batch is outside its configured bound.");
        }
        WriteRelationshipsRequest request = WriteRelationshipsRequest.newBuilder().addAllUpdates(updates).build();
        WriteRelationshipsResponse response;
        try {
            response = permissions.withDeadlineAfter(deadlineMillis, TimeUnit.MILLISECONDS).writeRelationships(request);
        } catch (io.grpc.StatusRuntimeException failure) {
            // Durable intent owns retry; only remove transport backoff for its next separately bounded attempt.
            if (failure.getStatus().getCode() == io.grpc.Status.Code.UNAVAILABLE
                    && permissions.getChannel() instanceof io.grpc.ManagedChannel channel) channel.resetConnectBackoff();
            throw failure;
        }
        if (!response.hasWrittenAt() || response.getWrittenAt().getToken().isBlank())
            throw new IllegalStateException("SpiceDB relationship write did not return a committed revision.");
        return response.getWrittenAt().getToken();
    }

    /** @return configured maximum for a bounded IAM projection batch */
    int maxBatchSize() { return maxBatchSize; }
}
