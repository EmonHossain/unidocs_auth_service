package com.unidocs.auth.security.spicedb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.authzed.api.v1.CheckPermissionRequest;
import com.authzed.api.v1.CheckPermissionResponse;
import com.authzed.api.v1.ObjectReference;
import com.authzed.api.v1.PermissionsServiceGrpc;
import com.authzed.api.v1.Relationship;
import com.authzed.api.v1.RelationshipUpdate;
import com.authzed.api.v1.SubjectReference;
import com.authzed.api.v1.WriteRelationshipsRequest;
import com.authzed.api.v1.WriteRelationshipsResponse;
import com.authzed.grpcutil.BearerToken;
import com.google.protobuf.Struct;
import com.google.protobuf.Value;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Server;
import io.grpc.ServerInterceptors;
import io.grpc.ServerBuilder;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class SpiceDbApiGatewayTests {
    /** Personal tuple ownership cannot cross IAM/Document credentials or resource generations. */
    @Test void individualProjectionCredentialsRemainSeparated() {
        String account=java.util.UUID.randomUUID().toString(),workspace=java.util.UUID.randomUUID().toString();
        WriteRelationshipsRequest policy=touch(relationship("individual_capability","a".repeat(64)+"_"+java.util.UUID.randomUUID(),"category_grantee","account",account));
        assertDoesNotThrow(()->SpiceDbApiGateway.validateWrite(policy));
        assertThrows(IllegalArgumentException.class,()->SpiceDbApiGateway.validateDocumentWrite(policy));
        WriteRelationshipsRequest live=touch(relationship("individual_content_workspace",workspace+"_r1","live","account","*"));
        assertDoesNotThrow(()->SpiceDbApiGateway.validateDocumentWrite(live));
        assertThrows(IllegalArgumentException.class,()->SpiceDbApiGateway.validateWrite(live));
        assertThrows(IllegalArgumentException.class,()->SpiceDbApiGateway.validateDocumentWrite(touch(
                relationship("individual_content_file",workspace+"_r1_"+java.util.UUID.randomUUID(),"parent","content_workspace",workspace+"_r1"))));
        assertThrows(IllegalArgumentException.class,()->SpiceDbApiGateway.validateDocumentWrite(touch(
                relationship("individual_content_file",workspace+"_r1_"+java.util.UUID.randomUUID(),"parent","individual_content_workspace",workspace+"_r2"))));
        assertThrows(IllegalArgumentException.class,()->SpiceDbApiGateway.validateDocumentWrite(touch(
                relationship("individual_content_workspace",workspace+"_r1","owner","account","*"))));
    }

    /** @param relationship exact idempotent fixture edge @return one bounded write */
    private static WriteRelationshipsRequest touch(Relationship relationship) {
        return WriteRelationshipsRequest.newBuilder().addUpdates(RelationshipUpdate.newBuilder()
                .setOperation(RelationshipUpdate.Operation.OPERATION_TOUCH).setRelationship(relationship)).build();
    }
    @Test
    void acceptsOnlyTheConfiguredCallerCredential() {
        byte[] expected = "Bearer caller-secret".getBytes(StandardCharsets.US_ASCII);

        assertTrue(SpiceDbApiGateway.isAuthorized(expected, expected.clone()));
        assertFalse(SpiceDbApiGateway.isAuthorized(expected, "Bearer other-secret".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(SpiceDbApiGateway.isAuthorized(expected, new byte[0]));
    }

    @Test
    void acceptsSchemaBoundPermissionChecks() {
        CheckPermissionRequest request = request("department", "capability_grant", "account");

        assertDoesNotThrow(() -> SpiceDbApiGateway.validateCheck(request));
        assertDoesNotThrow(() -> SpiceDbApiGateway.validateCheck(request("scope_capability", "category_grant", "account")));
        assertDoesNotThrow(() -> SpiceDbApiGateway.validateCheck(request("scope_capability", "scoped_grant", "account")));
        assertDoesNotThrow(() -> SpiceDbApiGateway.validateCheck(request("scope_capability", "responsibility_grant", "account")));
        assertDoesNotThrow(() -> SpiceDbApiGateway.validateCheck(request("organization", "explicit_deny", "account")));
    }

    @Test
    void rejectsUnknownResourcesPermissionsAndMismatchedSubjects() {
        assertThrows(IllegalArgumentException.class,
                () -> SpiceDbApiGateway.validateCheck(request("scope_capability", "grant", "account")));
        assertThrows(IllegalArgumentException.class,
                () -> SpiceDbApiGateway.validateCheck(request("organization", "write_schema", "account")));
        assertThrows(IllegalArgumentException.class,
                () -> SpiceDbApiGateway.validateCheck(request("team", "capability_grant", "operation")));
        assertThrows(IllegalArgumentException.class,
                () -> SpiceDbApiGateway.validateCheck(request("scope_capability", "category_grant", "operation")));
        assertThrows(IllegalArgumentException.class,
                () -> SpiceDbApiGateway.validateCheck(request("scope_capability", "responsibility_grant", "operation")));
        CheckPermissionRequest caveated = request("department", "member", "account").toBuilder()
                .setContext(Struct.newBuilder().putFields("untrusted", Value.newBuilder().setStringValue("value").build()))
                .build();
        assertThrows(IllegalArgumentException.class, () -> SpiceDbApiGateway.validateCheck(caveated));
    }

    @Test
    void relationshipWritesAreRestrictedToIdempotentOrganizationProjectionTuples() {
        WriteRelationshipsRequest allowed = WriteRelationshipsRequest.newBuilder().addUpdates(
                RelationshipUpdate.newBuilder().setOperation(RelationshipUpdate.Operation.OPERATION_TOUCH)
                        .setRelationship(relationship("team", "child", "parent", "team", "parent"))).build();
        assertDoesNotThrow(() -> SpiceDbApiGateway.validateWrite(allowed));

        WriteRelationshipsRequest accountRestriction = WriteRelationshipsRequest.newBuilder().addUpdates(
                RelationshipUpdate.newBuilder().setOperation(RelationshipUpdate.Operation.OPERATION_TOUCH)
                        .setRelationship(relationship("department", "department", "operation_restriction", "scope_operation", "scope-op"))).build();
        assertDoesNotThrow(() -> SpiceDbApiGateway.validateWrite(accountRestriction));
        WriteRelationshipsRequest categoryBinding = WriteRelationshipsRequest.newBuilder().addUpdates(
                RelationshipUpdate.newBuilder().setOperation(RelationshipUpdate.Operation.OPERATION_TOUCH)
                        .setRelationship(relationship("scope_capability", "cap", "category_grantee", "account", "account"))).build();
        assertDoesNotThrow(() -> SpiceDbApiGateway.validateWrite(categoryBinding));
        WriteRelationshipsRequest responsibilityBinding = WriteRelationshipsRequest.newBuilder().addUpdates(
                RelationshipUpdate.newBuilder().setOperation(RelationshipUpdate.Operation.OPERATION_TOUCH)
                        .setRelationship(relationship("scope_capability", "cap", "responsibility_grantee", "account", "account"))).build();
        assertDoesNotThrow(() -> SpiceDbApiGateway.validateWrite(responsibilityBinding));
        assertThrows(IllegalArgumentException.class,()->SpiceDbApiGateway.validateWrite(responsibilityBinding.toBuilder()
                .setUpdates(0,responsibilityBinding.getUpdates(0).toBuilder().setRelationship(
                        relationship("scope_capability","cap","responsibility_grantee","operation","operation"))).build()));

        WriteRelationshipsRequest unsupportedType = WriteRelationshipsRequest.newBuilder().addUpdates(
                RelationshipUpdate.newBuilder().setOperation(RelationshipUpdate.Operation.OPERATION_TOUCH)
                        .setRelationship(relationship("account", "a", "member", "account", "b"))).build();
        WriteRelationshipsRequest nonIdempotent = allowed.toBuilder().setUpdates(0,
                allowed.getUpdates(0).toBuilder().setOperation(RelationshipUpdate.Operation.OPERATION_CREATE)).build();
        WriteRelationshipsRequest wrongSubject = WriteRelationshipsRequest.newBuilder().addUpdates(
                RelationshipUpdate.newBuilder().setOperation(RelationshipUpdate.Operation.OPERATION_TOUCH)
                        .setRelationship(relationship("team", "child", "parent", "organization", "org"))).build();
        assertThrows(IllegalArgumentException.class, () -> SpiceDbApiGateway.validateWrite(unsupportedType));
        assertThrows(IllegalArgumentException.class, () -> SpiceDbApiGateway.validateWrite(nonIdempotent));
        assertThrows(IllegalArgumentException.class, () -> SpiceDbApiGateway.validateWrite(wrongSubject));
        assertThrows(IllegalArgumentException.class,
                () -> SpiceDbApiGateway.validateWrite(WriteRelationshipsRequest.getDefaultInstance()));
    }

    @Test
    void grpcGatewayRejectsUnknownCredentialsAndForwardsAllowedCheck() throws Exception {
        PermissionsServiceGrpc.PermissionsServiceBlockingStub backend = mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        when(backend.withDeadlineAfter(anyLong(), any(TimeUnit.class))).thenReturn(backend);
        CheckPermissionResponse expectedResponse = CheckPermissionResponse.newBuilder()
                .setPermissionship(CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION)
                .build();
        when(backend.checkPermission(any(CheckPermissionRequest.class))).thenReturn(expectedResponse);
        WriteRelationshipsResponse expectedWrite = WriteRelationshipsResponse.newBuilder().build();
        when(backend.writeRelationships(any(WriteRelationshipsRequest.class))).thenReturn(expectedWrite);

        Server server = ServerBuilder.forPort(0)
                .addService(ServerInterceptors.intercept(
                        new SpiceDbApiGateway.GatewayPermissionsService(backend, 500),
                        new SpiceDbApiGateway.CallerAuthenticationInterceptor("caller-secret", "projection-secret")))
                .build()
                .start();
        ManagedChannel channel = ManagedChannelBuilder.forAddress("127.0.0.1", server.getPort()).usePlaintext().build();
        try {
            PermissionsServiceGrpc.PermissionsServiceBlockingStub allowed = PermissionsServiceGrpc.newBlockingStub(channel)
                    .withCallCredentials(new BearerToken("caller-secret"));
            assertTrue(allowed.checkPermission(request("scope_capability", "responsibility_grant", "account"))
                    .equals(expectedResponse));
            verify(backend).checkPermission(any(CheckPermissionRequest.class));

            PermissionsServiceGrpc.PermissionsServiceBlockingStub denied = PermissionsServiceGrpc.newBlockingStub(channel)
                    .withCallCredentials(new BearerToken("wrong-secret"));
            StatusRuntimeException failure = assertThrows(StatusRuntimeException.class,
                    () -> denied.checkPermission(request("scope_capability", "responsibility_grant", "account")));
            assertTrue(failure.getStatus().getCode() == Status.Code.UNAUTHENTICATED);

            StatusRuntimeException deniedWrite = assertThrows(StatusRuntimeException.class,
                    () -> allowed.writeRelationships(writeRequest()));
            assertTrue(deniedWrite.getStatus().getCode() == Status.Code.PERMISSION_DENIED);

            PermissionsServiceGrpc.PermissionsServiceBlockingStub projector = PermissionsServiceGrpc.newBlockingStub(channel)
                    .withCallCredentials(new BearerToken("projection-secret"));
            assertTrue(projector.writeRelationships(writeRequest()).equals(expectedWrite));
            StatusRuntimeException deniedCheck = assertThrows(StatusRuntimeException.class,
                    () -> projector.checkPermission(request("scope_capability", "responsibility_grant", "account")));
            assertTrue(deniedCheck.getStatus().getCode() == Status.Code.PERMISSION_DENIED);
            verify(backend).writeRelationships(any(WriteRelationshipsRequest.class));
        } finally {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
            server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    private static CheckPermissionRequest request(String resourceType, String permission, String subjectType) {
        return CheckPermissionRequest.newBuilder()
                .setResource(ObjectReference.newBuilder().setObjectType(resourceType).setObjectId("resource-1"))
                .setPermission(permission)
                .setSubject(SubjectReference.newBuilder().setObject(
                        ObjectReference.newBuilder().setObjectType(subjectType).setObjectId("subject-1")))
                .build();
    }

    private static WriteRelationshipsRequest writeRequest() {
        return WriteRelationshipsRequest.newBuilder().addUpdates(
                RelationshipUpdate.newBuilder().setOperation(RelationshipUpdate.Operation.OPERATION_TOUCH)
                        .setRelationship(relationship("scope_capability", "cap", "responsibility_grantee", "account", "account"))).build();
    }

    /** Document writes cannot alter IAM facts or cross workspace/generation parent boundaries. */
    @Test
    void documentProjectionRejectsIamWritesAndCrossGenerationParents() {
        String workspace = "00000000-0000-0000-0000-000000000001";
        String child = workspace + "_r7_00000000-0000-0000-0000-000000000002";
        Relationship parent = relationship("content_directory", child, "parent", "content_workspace", workspace + "_r7");
        WriteRelationshipsRequest valid = documentWrite(parent);
        assertDoesNotThrow(() -> SpiceDbApiGateway.validateDocumentWrite(valid));
        assertDoesNotThrow(() -> SpiceDbApiGateway.validateDocumentWrite(valid.toBuilder().setUpdates(0,
                valid.getUpdates(0).toBuilder().setOperation(RelationshipUpdate.Operation.OPERATION_DELETE)).build()));
        assertThrows(IllegalArgumentException.class, () -> SpiceDbApiGateway.validateWrite(valid));
        for (Relationship invalid : java.util.List.of(
                relationship("content_directory", child, "parent", "content_workspace", workspace + "_r8"),
                relationship("content_directory", child, "parent", "content_workspace", "00000000-0000-0000-0000-000000000003_r7"),
                relationship("organization", workspace, "account_member", "account", workspace),
                relationship("content_workspace", workspace + "_r7", "owner", "account", "*"),
                relationship("content_workspace", workspace + "_r0", "owner", "account", workspace),
                relationship("content_workspace", workspace + "_r9223372036854775808", "owner", "account", workspace),
                parent.toBuilder().setSubject(parent.getSubject().toBuilder().setOptionalRelation("member")).build())) {
            assertThrows(IllegalArgumentException.class, () -> SpiceDbApiGateway.validateDocumentWrite(documentWrite(invalid)));
        }
        assertThrows(IllegalArgumentException.class, () -> SpiceDbApiGateway.validateDocumentWrite(
                valid.toBuilder().setUpdates(0,valid.getUpdates(0).toBuilder().setOperation(RelationshipUpdate.Operation.OPERATION_CREATE)).build()));
        assertThrows(IllegalArgumentException.class, () -> SpiceDbApiGateway.validateDocumentWrite(WriteRelationshipsRequest.getDefaultInstance()));
    }

    /** Both IAM group kinds can back a managed audience, without permitting arbitrary subject kinds. */
    @Test
    void documentProjectionAcceptsDepartmentAndTeamAudiencesOnly() {
        String id = "00000000-0000-0000-0000-000000000001";
        for (String kind : java.util.List.of("department", "team")) {
            assertDoesNotThrow(() -> SpiceDbApiGateway.validateDocumentWrite(documentWrite(
                    relationship("content_workspace",id+"_r1","audience",kind,id))));
        }
        assertThrows(IllegalArgumentException.class, () -> SpiceDbApiGateway.validateDocumentWrite(documentWrite(
                relationship("content_workspace",id+"_r1","audience","account",id))));
    }

    /** The actual gRPC interceptor separates Document, IAM and permission-check credentials. */
    @Test
    void documentCredentialCannotCheckPermissionsOrWriteIamRelationships() throws Exception {
        PermissionsServiceGrpc.PermissionsServiceBlockingStub backend = mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        when(backend.withDeadlineAfter(anyLong(), any(TimeUnit.class))).thenReturn(backend);
        when(backend.writeRelationships(any())).thenReturn(WriteRelationshipsResponse.getDefaultInstance());
        Server server = ServerBuilder.forPort(0).addService(ServerInterceptors.intercept(
                new SpiceDbApiGateway.GatewayPermissionsService(backend,500),
                new SpiceDbApiGateway.CallerAuthenticationInterceptor("check-fixture","iam-fixture","document-fixture"))).build().start();
        ManagedChannel channel = ManagedChannelBuilder.forAddress("127.0.0.1",server.getPort()).usePlaintext().build();
        try {
            PermissionsServiceGrpc.PermissionsServiceBlockingStub document = PermissionsServiceGrpc.newBlockingStub(channel)
                    .withCallCredentials(new BearerToken("document-fixture"));
            String id = "00000000-0000-0000-0000-000000000001";
            assertDoesNotThrow(() -> document.writeRelationships(documentWrite(
                    relationship("content_workspace",id+"_r1","organization","organization",id))));
            assertTrue(assertThrows(StatusRuntimeException.class, () -> document.checkPermission(
                    request("content_workspace","view","account"))).getStatus().getCode()==Status.Code.PERMISSION_DENIED);
            assertTrue(assertThrows(StatusRuntimeException.class, () -> document.writeRelationships(documentWrite(
                    relationship("organization",id,"account_member","account",id)))).getStatus().getCode()==Status.Code.INVALID_ARGUMENT);
            PermissionsServiceGrpc.PermissionsServiceBlockingStub iam = PermissionsServiceGrpc.newBlockingStub(channel)
                    .withCallCredentials(new BearerToken("iam-fixture"));
            assertTrue(assertThrows(StatusRuntimeException.class, () -> iam.writeRelationships(documentWrite(
                    relationship("content_workspace",id+"_r1","owner","account",id)))).getStatus().getCode()==Status.Code.INVALID_ARGUMENT);
        } finally { channel.shutdownNow();server.shutdownNow(); }
    }

    /** @param tuple exact relationship @return idempotent request without extra write options */
    private static WriteRelationshipsRequest documentWrite(Relationship tuple) {
        return WriteRelationshipsRequest.newBuilder().addUpdates(RelationshipUpdate.newBuilder()
                .setOperation(RelationshipUpdate.Operation.OPERATION_TOUCH).setRelationship(tuple)).build();
    }

    private static Relationship relationship(String resourceType, String resourceId, String relation,
            String subjectType, String subjectId) {
        return Relationship.newBuilder()
                .setResource(ObjectReference.newBuilder().setObjectType(resourceType).setObjectId(resourceId))
                .setRelation(relation)
                .setSubject(SubjectReference.newBuilder().setObject(
                        ObjectReference.newBuilder().setObjectType(subjectType).setObjectId(subjectId)))
                .build();
    }
}
