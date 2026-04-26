package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.CheckPermissionRequest;
import com.authzed.api.v1.CheckPermissionResponse;
import com.authzed.api.v1.PermissionsServiceGrpc;
import com.authzed.api.v1.Relationship;
import com.authzed.api.v1.RelationshipUpdate;
import com.authzed.api.v1.WriteRelationshipsRequest;
import com.authzed.api.v1.WriteRelationshipsResponse;
import com.authzed.grpcutil.BearerToken;
import com.sun.net.httpserver.HttpServer;
import io.grpc.CallCredentials;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/** Authenticates separate check and optional relationship-writer callers at the SpiceDB boundary. */
public final class SpiceDbApiGateway {
    private static final Metadata.Key<String> AUTHORIZATION = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
    private static final Context.Key<String> CALLER_KIND = Context.key("spicedb-gateway-caller-kind");
    private static final int MAX_RPC_DEADLINE_MILLIS = 10_000;
    private static final int MAX_RELATIONSHIP_BATCH_SIZE = 1_000;
    private static final Map<String, Set<String>> PERMISSIONS_BY_RESOURCE = Map.ofEntries(
            Map.entry("individual_capability", Set.of("grant")),
            Map.entry("individual_group", Set.of("member")),
            Map.entry("individual_content_workspace", Set.of("available", "view", "edit")),
            Map.entry("individual_content_directory", Set.of("available", "view", "edit")),
            Map.entry("individual_content_file", Set.of("available", "view", "edit")),
            Map.entry("organization", Set.of("member", "capability_grant", "category_capability_grant", "explicit_deny")),
            Map.entry("department", Set.of("member", "capability_grant", "category_capability_grant", "explicit_deny")),
            Map.entry("team", Set.of("member", "capability_grant", "category_capability_grant", "explicit_deny")),
            Map.entry("scope_capability", Set.of("category_grant", "scoped_grant", "responsibility_grant")),
            Map.entry("scope_operation", Set.of("denied")),
            Map.entry("content_workspace", Set.of("available", "view", "edit")),
            Map.entry("content_directory", Set.of("available", "view", "edit")),
            Map.entry("content_file", Set.of("available", "view", "edit")));

    private SpiceDbApiGateway() { }

    public static void main(String[] arguments) throws IOException, InterruptedException {
        if (arguments.length == 1 && "health".equals(arguments[0])) return;
        if (arguments.length != 0) throw new IllegalArgumentException("Usage: SpiceDbApiGateway");
        if (!"true".equalsIgnoreCase(System.getenv("SPICEDB_GATEWAY_ENABLED"))) {
            throw new IllegalStateException("Set SPICEDB_GATEWAY_ENABLED=true to start the SpiceDB API gateway.");
        }

        String callerToken = requiredEnvironment("SPICEDB_GATEWAY_CLIENT_TOKEN");
        String relationshipWriterToken = optionalEnvironment("SPICEDB_GATEWAY_PROJECTION_TOKEN");
        String documentWriterToken = optionalEnvironment("SPICEDB_GATEWAY_DOCUMENT_PROJECTION_TOKEN");
        if (!documentWriterToken.isBlank() && (documentWriterToken.equals(callerToken)
                || documentWriterToken.equals(relationshipWriterToken))) {
            throw new IllegalStateException("Document projection requires a distinct credential.");
        }
        if (!relationshipWriterToken.isBlank() && isAuthorized(
                ("Bearer " + callerToken).getBytes(StandardCharsets.US_ASCII),
                ("Bearer " + relationshipWriterToken).getBytes(StandardCharsets.US_ASCII))) {
            throw new IllegalStateException("SpiceDB check and relationship-writer credentials must be distinct.");
        }
        String backendToken = requiredEnvironment("SPICEDB_GATEWAY_BACKEND_TOKEN");
        if (!documentWriterToken.isBlank() && documentWriterToken.equals(backendToken)) {
            throw new IllegalStateException("Document must not receive the gateway backend credential.");
        }
        String endpoint = requiredEnvironment("SPICEDB_GATEWAY_BACKEND_ENDPOINT");
        boolean plaintext = "true".equalsIgnoreCase(System.getenv("SPICEDB_GATEWAY_BACKEND_PLAINTEXT"));
        if (plaintext && !"spicedb".equals(host(endpoint))) {
            throw new IllegalArgumentException("Plaintext gateway upstream is restricted to the private Compose SpiceDB host.");
        }
        long deadlineMillis = parseDeadline(System.getenv("SPICEDB_GATEWAY_RPC_DEADLINE_MILLIS"));

        ManagedChannelBuilder<?> channelBuilder = ManagedChannelBuilder.forTarget(endpoint);
        if (plaintext) channelBuilder.usePlaintext();
        else channelBuilder.useTransportSecurity();
        ManagedChannel channel = channelBuilder.build();
        CallCredentials backendCredentials = new BearerToken(backendToken);
        PermissionsServiceGrpc.PermissionsServiceBlockingStub backend = PermissionsServiceGrpc
                .newBlockingStub(channel).withCallCredentials(backendCredentials);

        Server server = io.grpc.ServerBuilder.forPort(50051)
                .addService(ServerInterceptors.intercept(new GatewayPermissionsService(backend, deadlineMillis),
                        new CallerAuthenticationInterceptor(callerToken, relationshipWriterToken, documentWriterToken)))
                .build()
                .start();
        HttpServer healthServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 8080), 0);
        healthServer.createContext("/health", exchange -> {
            byte[] body = "ok".getBytes(StandardCharsets.US_ASCII);
            exchange.sendResponseHeaders(200, body.length);
            try (var output = exchange.getResponseBody()) { output.write(body); }
        });
        healthServer.start();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            healthServer.stop(0);
            server.shutdown();
            channel.shutdownNow();
        }, "spicedb-api-gateway-shutdown"));
        server.awaitTermination();
    }

    static final class GatewayPermissionsService extends PermissionsServiceGrpc.PermissionsServiceImplBase {
        private final PermissionsServiceGrpc.PermissionsServiceBlockingStub backend;
        private final long deadlineMillis;

        GatewayPermissionsService(PermissionsServiceGrpc.PermissionsServiceBlockingStub backend, long deadlineMillis) {
            this.backend = backend;
            this.deadlineMillis = deadlineMillis;
        }

        @Override
        public void checkPermission(CheckPermissionRequest request, StreamObserver<CheckPermissionResponse> responseObserver) {
            try {
                if (!"check".equals(CALLER_KIND.get())) {
                    throw new SecurityException("Permission checks require the check credential.");
                }
                validateCheck(request);
                CheckPermissionResponse response = backend.withDeadlineAfter(deadlineMillis, TimeUnit.MILLISECONDS)
                        .checkPermission(request);
                responseObserver.onNext(response);
                responseObserver.onCompleted();
            } catch (StatusRuntimeException failure) {
                responseObserver.onError(failure);
            } catch (SecurityException denied) {
                responseObserver.onError(Status.PERMISSION_DENIED.withDescription(denied.getMessage()).asRuntimeException());
            } catch (IllegalArgumentException invalidRequest) {
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(invalidRequest.getMessage()).asRuntimeException());
            }
        }

        @Override
        public void writeRelationships(WriteRelationshipsRequest request,
                StreamObserver<WriteRelationshipsResponse> responseObserver) {
            try {
                String caller = CALLER_KIND.get();
                if (!"relationship-writer".equals(caller) && !"document-writer".equals(caller)) {
                    throw new SecurityException("Relationship writes require the relationship-writer credential.");
                }
                if ("document-writer".equals(caller)) validateDocumentWrite(request);
                else validateWrite(request);
                WriteRelationshipsResponse response = backend.withDeadlineAfter(deadlineMillis, TimeUnit.MILLISECONDS)
                        .writeRelationships(request);
                responseObserver.onNext(response);
                responseObserver.onCompleted();
            } catch (StatusRuntimeException failure) {
                responseObserver.onError(failure);
            } catch (SecurityException denied) {
                responseObserver.onError(Status.PERMISSION_DENIED.withDescription(denied.getMessage()).asRuntimeException());
            } catch (IllegalArgumentException invalidRequest) {
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(invalidRequest.getMessage()).asRuntimeException());
            }
        }
    }

    static final class CallerAuthenticationInterceptor implements ServerInterceptor {
        private final byte[] checkAuthorization;
        private final byte[] relationshipWriterAuthorization;
        private final byte[] documentWriterAuthorization;

        CallerAuthenticationInterceptor(String token) {
            this(token, "");
        }

        CallerAuthenticationInterceptor(String checkToken, String relationshipWriterToken) {
            this(checkToken, relationshipWriterToken, "");
        }

        /** Separates IAM and Document tuple ownership at the gateway. */
        CallerAuthenticationInterceptor(String checkToken, String relationshipWriterToken, String documentWriterToken) {
            checkAuthorization = ("Bearer " + checkToken).getBytes(StandardCharsets.US_ASCII);
            relationshipWriterAuthorization = relationshipWriterToken == null || relationshipWriterToken.isBlank() ? new byte[0]
                    : ("Bearer " + relationshipWriterToken).getBytes(StandardCharsets.US_ASCII);
            documentWriterAuthorization = documentWriterToken == null || documentWriterToken.isBlank() ? new byte[0]
                    : ("Bearer " + documentWriterToken).getBytes(StandardCharsets.US_ASCII);
        }

        @Override
        public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call,
                Metadata headers, ServerCallHandler<ReqT, RespT> next) {
            String authorization = headers.get(AUTHORIZATION);
            byte[] supplied = authorization == null ? new byte[0] : authorization.getBytes(StandardCharsets.US_ASCII);
            String callerKind;
            if (isAuthorized(checkAuthorization, supplied)) {
                callerKind = "check";
            } else if (relationshipWriterAuthorization.length > 0 && isAuthorized(relationshipWriterAuthorization, supplied)) {
                callerKind = "relationship-writer";
            } else if (documentWriterAuthorization.length > 0 && isAuthorized(documentWriterAuthorization, supplied)) {
                callerKind = "document-writer";
            } else {
                call.close(Status.UNAUTHENTICATED.withDescription("Invalid SpiceDB gateway credential."), new Metadata());
                return new ServerCall.Listener<>() { };
            }
            return Contexts.interceptCall(Context.current().withValue(CALLER_KIND, callerKind), call, headers, next);
        }
    }

    static boolean isAuthorized(byte[] expectedAuthorization, byte[] suppliedAuthorization) {
        return MessageDigest.isEqual(expectedAuthorization, suppliedAuthorization);
    }

    static void validateCheck(CheckPermissionRequest request) {
        String resourceType = request.getResource().getObjectType();
        String permission = request.getPermission();
        Set<String> allowedPermissions = PERMISSIONS_BY_RESOURCE.get(resourceType);
        if (allowedPermissions == null || !allowedPermissions.contains(permission)) {
            throw new IllegalArgumentException("Requested SpiceDB resource or permission is not exposed by this gateway.");
        }
        String subjectType = request.getSubject().getObject().getObjectType();
        if (("explicit_deny".equals(permission) && !Set.of("operation", "account").contains(subjectType))
                || (!"explicit_deny".equals(permission) && !"account".equals(subjectType))) {
            throw new IllegalArgumentException("Requested SpiceDB subject type is not valid for this permission.");
        }
        if (!request.getContext().getFieldsMap().isEmpty()) {
            throw new IllegalArgumentException("Caveat context is not exposed by this gateway.");
        }
    }

    static void validateWrite(WriteRelationshipsRequest request) {
        if (request == null || request.getUpdatesCount() < 1 || request.getUpdatesCount() > MAX_RELATIONSHIP_BATCH_SIZE
                || request.getOptionalPreconditionsCount() != 0 || request.hasOptionalTransactionMetadata()) {
            throw new IllegalArgumentException("Relationship write batch is empty, oversized or contains unsupported metadata.");
        }
        for (RelationshipUpdate update : request.getUpdatesList()) {
            if (update.getOperation() != RelationshipUpdate.Operation.OPERATION_TOUCH
                    && update.getOperation() != RelationshipUpdate.Operation.OPERATION_DELETE) {
                throw new IllegalArgumentException("Only idempotent relationship touch and exact-tuple delete are exposed.");
            }
            validateRelationship(update.getRelationship());
        }
    }

    /**
     * Restricts Document's worker to resource tuples; it cannot modify IAM authority.
     * @param request bounded, idempotent resource delta
     * @throws IllegalArgumentException for unsupported tuples or write options
     */
    static void validateDocumentWrite(WriteRelationshipsRequest request) {
        if (request == null || request.getUpdatesCount() < 1 || request.getUpdatesCount() > MAX_RELATIONSHIP_BATCH_SIZE
                || request.getOptionalPreconditionsCount() != 0 || request.hasOptionalTransactionMetadata()) {
            throw new IllegalArgumentException("Invalid Document relationship batch.");
        }
        for (RelationshipUpdate update : request.getUpdatesList()) {
            Relationship relationship = update.getRelationship();
            String resourceType = relationship.getResource().getObjectType();
            String resourceId = relationship.getResource().getObjectId();
            String subjectType = relationship.getSubject().getObject().getObjectType();
            String subjectId = relationship.getSubject().getObject().getObjectId();
            String relation = relationship.getRelation();
            if (resourceType.startsWith("individual_content_")) {
                validateIndividualContent(update);
                continue;
            }
            boolean resource = Set.of("content_workspace", "content_directory", "content_file").contains(resourceType);
            boolean allowed = switch (relation) {
                case "organization", "live" -> "organization".equals(subjectType);
                case "owner", "viewer", "editor" -> "account".equals(subjectType);
                case "audience" -> Set.of("organization", "department", "team").contains(subjectType);
                case "parent" -> ("content_directory".equals(resourceType) || "content_file".equals(resourceType))
                        && Set.of("content_workspace", "content_directory").contains(subjectType)
                        && sameContentGeneration(resourceId, subjectId);
                default -> false;
            };
            if (!resource || !allowed || !validContentIdentity(resourceType, resourceId)
                    || (subjectType.startsWith("content_") ? !validContentIdentity(subjectType, subjectId) : !canonicalUuid(subjectId))
                    || !relationship.getSubject().getOptionalRelation().isBlank()
                    || relationship.hasOptionalCaveat() || relationship.hasOptionalExpiresAt()
                    || update.getOperation() != RelationshipUpdate.Operation.OPERATION_TOUCH
                       && update.getOperation() != RelationshipUpdate.Operation.OPERATION_DELETE) {
                throw new IllegalArgumentException("Relationship is outside Document ownership.");
            }
        }
    }

    /**
     * Keeps child identities inside a canonical workspace and positive source generation.
     * @param type schema resource type
     * @param id workspace/generation-qualified object identity
     * @return whether the identity has exactly the expected components
     */
    private static boolean validContentIdentity(String type, String id) {
        String[] parts = id.split("_", -1);
        int expected = type.endsWith("content_workspace") ? 2 : 3;
        if (parts.length != expected || !canonicalUuid(parts[0]) || !parts[1].matches("r[1-9][0-9]{0,18}")) return false;
        try {
            if (Long.parseLong(parts[1].substring(1)) < 1) return false;
        } catch (NumberFormatException invalid) { return false; }
        return expected == 2 || canonicalUuid(parts[2]);
    }

    /** @param value direct principal/scope identity @return whether it is a canonical UUID */
    private static boolean canonicalUuid(String value) {
        try { return java.util.UUID.fromString(value).toString().equals(value); }
        catch (IllegalArgumentException invalid) { return false; }
    }

    /**
     * Keeps Document's personal writes separate from IAM group membership and policy.
     * @param update exact idempotent Document resource delta
     * @throws IllegalArgumentException for cross-context edges, wildcards outside liveness or unsupported options
     */
    private static void validateIndividualContent(RelationshipUpdate update) {
        Relationship tuple = update.getRelationship();
        String type = tuple.getResource().getObjectType(), id = tuple.getResource().getObjectId();
        String subject = tuple.getSubject().getObject().getObjectType(), subjectId = tuple.getSubject().getObject().getObjectId();
        boolean resource = Set.of("individual_content_workspace", "individual_content_directory", "individual_content_file").contains(type);
        boolean allowed = switch (tuple.getRelation()) {
            case "live" -> "account".equals(subject) && "*".equals(subjectId);
            case "owner", "viewer", "editor" -> "account".equals(subject) && canonicalUuid(subjectId);
            case "audience" -> "individual_content_workspace".equals(type) && "individual_group".equals(subject) && canonicalUuid(subjectId);
            case "parent" -> !"individual_content_workspace".equals(type)
                    && Set.of("individual_content_workspace", "individual_content_directory").contains(subject)
                    && validContentIdentity(subject, subjectId) && sameContentGeneration(id, subjectId);
            default -> false;
        };
        if (!resource || !allowed || !validContentIdentity(type, id)
                || !tuple.getSubject().getOptionalRelation().isBlank() || tuple.hasOptionalCaveat() || tuple.hasOptionalExpiresAt()
                || update.getOperation() != RelationshipUpdate.Operation.OPERATION_TOUCH
                   && update.getOperation() != RelationshipUpdate.Operation.OPERATION_DELETE)
            throw new IllegalArgumentException("Relationship is outside Document personal ownership.");
    }

    /**
     * Prevents parent edges from crossing either workspace or immutable source generation.
     * @param resource tenant-qualified child identity
     * @param parent tenant-qualified ancestor identity
     * @return whether both objects belong to exactly the same resource snapshot
     */
    private static boolean sameContentGeneration(String resource, String parent) {
        String[] childParts = resource.split("_", 3);
        String[] parentParts = parent.split("_", 3);
        return childParts.length >= 2 && parentParts.length >= 2
                && childParts[0].equals(parentParts[0]) && childParts[1].equals(parentParts[1]);
    }

    private static void validateRelationship(Relationship relationship) {
        if (relationship == null || !relationship.hasResource() || !relationship.hasSubject()
                || relationship.hasOptionalCaveat() || relationship.hasOptionalExpiresAt()) {
            throw new IllegalArgumentException("Relationships require a resource and direct, non-caveated subject.");
        }
        String resourceType = relationship.getResource().getObjectType();
        String relation = relationship.getRelation();
        String subjectType = relationship.getSubject().getObject().getObjectType();
        String subjectRelation = relationship.getSubject().getOptionalRelation();
        String resourceId = relationship.getResource().getObjectId();
        String subjectId = relationship.getSubject().getObject().getObjectId();
        boolean allowed = switch (resourceType + "." + relation + "." + subjectType) {
            case "organization.account_member.account", "organization.capability.scope_capability",
                    "organization.denied_operation.operation", "organization.category_capability.scope_capability",
                    "department.organization.organization", "department.category_capability.scope_capability",
                    "department.account_member.account", "department.capability.scope_capability",
                    "department.denied_operation.operation", "team.organization.organization",
                    "team.account_member.account", "team.capability.scope_capability",
                    "team.category_capability.scope_capability",
                    "team.denied_operation.operation", "team.operation_restriction.scope_operation",
                    "department.operation_restriction.scope_operation", "organization.operation_restriction.scope_operation",
                    "team.parent.department", "team.parent.team", "department.parent.department", "department.parent.team",
                    "scope_capability.grantee.account", "scope_capability.category_grantee.account",
                    "scope_capability.scoped_grantee.account", "scope_capability.responsibility_grantee.account",
                    "individual_capability.category_grantee.account", "individual_capability.local_grantee.account",
                    "individual_group.participant.account",
                    "scope_capability.parent.scope_capability", "scope_operation.denied_account.account",
                    "scope_operation.parent.scope_operation" -> true;
            default -> false;
        };
        if ("individual_capability".equals(resourceType)
                && (!resourceId.matches("[0-9a-f]{64}_[0-9a-f-]{36}")
                    || !canonicalUuid(resourceId.substring(65)) || !canonicalUuid(subjectId))) {
            throw new IllegalArgumentException("Invalid personal capability identity.");
        }
        if ("individual_group".equals(resourceType) && (!canonicalUuid(resourceId) || !canonicalUuid(subjectId)))
            throw new IllegalArgumentException("Invalid personal group identity.");
        if (!allowed || resourceId.isBlank() || subjectId.isBlank() || !subjectRelation.isBlank()) {
            throw new IllegalArgumentException("Relationship type, relation or subject is outside the organization-sync contract.");
        }
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException("Required gateway configuration is missing: " + name);
        return value;
    }

    private static String optionalEnvironment(String name) {
        String value = System.getenv(name);
        return value == null ? "" : value.trim();
    }

    private static long parseDeadline(String rawValue) {
        long value = rawValue == null || rawValue.isBlank() ? 500 : Long.parseLong(rawValue);
        if (value < 1 || value > MAX_RPC_DEADLINE_MILLIS) {
            throw new IllegalArgumentException("Gateway RPC deadline must be between 1 and 10000 milliseconds.");
        }
        return value;
    }

    private static String host(String endpoint) {
        try {
            return URI.create("https://" + endpoint).getHost();
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("Invalid SpiceDB gateway backend endpoint.");
        }
    }
}
