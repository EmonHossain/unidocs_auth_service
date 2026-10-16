package com.unidocs.auth.security.spicedb;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.authzed.api.v1.CheckPermissionRequest;
import com.authzed.api.v1.CheckPermissionResponse;
import com.authzed.api.v1.PermissionsServiceGrpc;
import com.authzed.api.v1.WriteRelationshipsRequest;
import com.authzed.api.v1.WriteRelationshipsResponse;
import com.authzed.api.v1.RelationshipUpdate;
import com.authzed.api.v1.ZedToken;
import static org.mockito.ArgumentMatchers.any;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class SpiceDbPermissionClientTests {
    /** Unavailability removes only connection backoff; the failed decision is not retried or allowed. */
    @Test void unavailableTransportCanReconnectOnTheNextFreshAttempt() {
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub=mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        io.grpc.ManagedChannel channel=mock(io.grpc.ManagedChannel.class);
        when(stub.getChannel()).thenReturn(channel);when(stub.withDeadlineAfter(250,TimeUnit.MILLISECONDS)).thenReturn(stub);
        when(stub.checkPermission(any())).thenThrow(io.grpc.Status.UNAVAILABLE.asRuntimeException());
        assertThrows(io.grpc.StatusRuntimeException.class,()->new SpiceDbPermissionClient(stub,250).checkPermission(CheckPermissionRequest.getDefaultInstance()));
        verify(channel).resetConnectBackoff();verify(stub).checkPermission(any());
    }

    /** A failed write remains unacknowledged and leaves durable intent responsible for retry. */
    @Test void unavailableWriteDoesNotRetryOrInventAcknowledgement() {
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub=mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        io.grpc.ManagedChannel channel=mock(io.grpc.ManagedChannel.class);
        when(stub.getChannel()).thenReturn(channel);when(stub.withDeadlineAfter(250,TimeUnit.MILLISECONDS)).thenReturn(stub);
        when(stub.writeRelationships(any())).thenThrow(io.grpc.Status.UNAVAILABLE.asRuntimeException());
        SpiceDbRelationshipWriter writer=new SpiceDbRelationshipWriter(stub,250,1);
        assertThrows(io.grpc.StatusRuntimeException.class,()->writer.writeRelationships(java.util.List.of(new SpiceDbRelationship(
                "individual_group",java.util.UUID.randomUUID().toString(),"participant","account",java.util.UUID.randomUUID().toString())
                .update(RelationshipUpdate.Operation.OPERATION_TOUCH))));
        verify(channel).resetConnectBackoff();verify(stub).writeRelationships(any());
    }
    /**
     * Requires committed revision evidence while retaining the configured write deadline.
     * @param result missing, blank or definitive gateway acknowledgement
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"missing", "blank", "committed"})
    void relationshipWriteRequiresCommittedRevision(String result) {
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub = mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        WriteRelationshipsResponse response = result.equals("missing") ? WriteRelationshipsResponse.getDefaultInstance()
                : WriteRelationshipsResponse.newBuilder().setWrittenAt(ZedToken.newBuilder()
                        .setToken(result.equals("committed") ? "committed-token" : "")).build();
        when(stub.withDeadlineAfter(250, TimeUnit.MILLISECONDS)).thenReturn(stub);
        when(stub.writeRelationships(any(WriteRelationshipsRequest.class))).thenReturn(response);
        SpiceDbRelationshipWriter writer = new SpiceDbRelationshipWriter(stub, 250, 1);
        java.util.List<RelationshipUpdate> batch = java.util.List.of(new SpiceDbRelationship(
                "team", "scope", "account_member", "account", "actor")
                .update(RelationshipUpdate.Operation.OPERATION_TOUCH));

        if (result.equals("committed")) assertEquals("committed-token", writer.writeRelationships(batch));
        else assertThrows(IllegalStateException.class, () -> writer.writeRelationships(batch));
        verify(stub).withDeadlineAfter(250, TimeUnit.MILLISECONDS);
    }

    @Test
    void checkUsesServerBuiltRequestAndBoundedRpcDeadline() {
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub = mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        CheckPermissionRequest request = CheckPermissionRequest.newBuilder().build();
        CheckPermissionResponse expected = CheckPermissionResponse.newBuilder().build();
        when(stub.withDeadlineAfter(250, TimeUnit.MILLISECONDS)).thenReturn(stub);
        when(stub.checkPermission(request)).thenReturn(expected);
        SpiceDbPermissionClient client = new SpiceDbPermissionClient(stub, 250);

        assertSame(expected, client.checkPermission(request));
        verify(stub).withDeadlineAfter(250, TimeUnit.MILLISECONDS);
        verify(stub).checkPermission(request);
    }

    @Test
    void rejectsMissingRequest() {
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub = mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        SpiceDbPermissionClient client = new SpiceDbPermissionClient(stub, 500);

        assertThrows(IllegalArgumentException.class, () -> client.checkPermission(null));
    }
}
