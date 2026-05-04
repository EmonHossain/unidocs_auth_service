package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.CheckPermissionRequest;
import com.authzed.api.v1.CheckPermissionResponse;
import com.authzed.api.v1.Consistency;
import com.authzed.api.v1.DeleteRelationshipsRequest;
import com.authzed.api.v1.ObjectReference;
import com.authzed.api.v1.PermissionsServiceGrpc;
import com.authzed.api.v1.ReadSchemaRequest;
import com.authzed.api.v1.Relationship;
import com.authzed.api.v1.RelationshipFilter;
import com.authzed.api.v1.RelationshipUpdate;
import com.authzed.api.v1.SchemaServiceGrpc;
import com.authzed.api.v1.SubjectReference;
import com.authzed.api.v1.WriteRelationshipsRequest;
import com.authzed.api.v1.WriteSchemaRequest;
import com.authzed.grpcutil.BearerToken;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/** Explicit local operator entry point. Never loaded as an HTTP endpoint or application bean. */
public final class SpiceDbSchemaOperator {
    private static final String SCHEMA_RESOURCE = "/spicedb/schema/individual_content_v4.zed";
    private static final long RPC_DEADLINE_MILLIS = 10_000;

    private SpiceDbSchemaOperator() { }

    /**
     * Runs an explicit schema command or a read-only, acknowledged-ledger inventory check.
     * @param arguments install/validate, inventory/content-inventory with a manifest, or backup-schema with a new file
     * @throws IOException when the versioned schema or inventory manifest cannot be read
     */
    public static void main(String[] arguments) throws IOException {
        boolean inventory=arguments.length==2&&List.of("inventory","content-inventory","individual-inventory").contains(arguments[0]);
        boolean backup=arguments.length==2&&"backup-schema".equals(arguments[0]);
        if (!inventory && !backup && (arguments.length != 1 || !List.of("install", "validate").contains(arguments[0]))) {
            throw new IllegalArgumentException("Usage: SpiceDbSchemaOperator <install|validate>, <inventory|content-inventory> <manifest>, or backup-schema <new-file>");
        }
        if (!"true".equalsIgnoreCase(System.getenv("SPICEDB_SCHEMA_OPERATOR_ENABLED"))) {
            throw new IllegalStateException("Set SPICEDB_SCHEMA_OPERATOR_ENABLED=true for an explicit schema operation.");
        }
        String endpoint = requiredEnvironment("SPICEDB_SCHEMA_OPERATOR_ENDPOINT");
        String token = requiredEnvironment("SPICEDB_SCHEMA_OPERATOR_TOKEN");
        boolean plaintext = "true".equalsIgnoreCase(System.getenv("SPICEDB_SCHEMA_OPERATOR_PLAINTEXT"));
        if (plaintext && !"spicedb".equals(host(endpoint))) {
            throw new IllegalArgumentException("Plaintext schema operations are restricted to the private Compose SpiceDB host.");
        }

        String schema;
        try (InputStream input = SpiceDbSchemaOperator.class.getResourceAsStream(SCHEMA_RESOURCE)) {
            if (input == null) throw new IllegalStateException("Versioned SpiceDB schema resource is missing.");
            schema = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }

        ManagedChannelBuilder<?> builder = ManagedChannelBuilder.forTarget(endpoint);
        if (plaintext) builder.usePlaintext();
        else builder.useTransportSecurity();
        ManagedChannel channel = builder.build();
        try {
            BearerToken credentials = new BearerToken(token);
            if(inventory) {
                Path manifest=Path.of(arguments[1]);
                if(Files.size(manifest)>8_000_000)throw new IllegalArgumentException("Inventory manifest is too large.");
                SpiceDbProjectionInventory reader=new SpiceDbProjectionInventory(
                        PermissionsServiceGrpc.newBlockingStub(channel).withCallCredentials(credentials));
                List<String> lines=Files.readAllLines(manifest,StandardCharsets.UTF_8);
                int count=switch(arguments[0]) {
                    case "content-inventory" -> reader.verifyContent(lines);
                    case "individual-inventory" -> reader.verifyIndividual(lines);
                    default -> reader.verify(lines);
                };
                System.out.println("SpiceDB physical inventory matched "+count+" acknowledged tuples; no writes issued");
                return;
            }
            SchemaServiceGrpc.SchemaServiceBlockingStub schemas = SchemaServiceGrpc.newBlockingStub(channel)
                    .withCallCredentials(credentials).withDeadlineAfter(RPC_DEADLINE_MILLIS, TimeUnit.MILLISECONDS);
            if (backup) {
                String currentSchema=schemas.readSchema(ReadSchemaRequest.getDefaultInstance()).getSchemaText();
                Files.writeString(Path.of(arguments[1]),currentSchema,StandardCharsets.UTF_8,
                        java.nio.file.StandardOpenOption.CREATE_NEW);
                System.out.println("Current SpiceDB schema backed up; no schema or relationship writes issued");
                return;
            }
            schemas.writeSchema(WriteSchemaRequest.newBuilder().setSchema(schema).build());
            if ("validate".equals(arguments[0])) {
                PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions = PermissionsServiceGrpc
                        .newBlockingStub(channel).withCallCredentials(credentials);
                validateRelationships(permissions);
                validateContentRelationships(permissions);
                validateIndividualRelationships(permissions);
            }
            System.out.println("SpiceDB schema " + schemaVersion(schema) + " "
                    + ("install".equals(arguments[0]) ? "installed" : "validated with relationship assertions"));
        } finally {
            channel.shutdownNow();
        }
    }

    private static void validateRelationships(PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions) {
        String suffix = UUID.randomUUID().toString();
        String organizationId = "phase2-org-" + suffix;
        String departmentId = "phase2-dept-" + suffix;
        String rootTeamId = "phase2-root-team-" + suffix;
        String childTeamId = "phase2-child-team-" + suffix;
        String childCapabilityId = "phase2-cap-child-" + suffix;
        String parentCapabilityId = "phase2-cap-parent-" + suffix;
        String otherCapabilityId = "phase3-cap-other-" + suffix;
        String accountId = "phase2-account-" + suffix;
        String otherAccountId = "phase2-other-account-" + suffix;
        String operationId = "phase2-operation-" + suffix;
        String rootOperationId = "phase2-scope-operation-root-" + suffix;
        String childOperationId = "phase2-scope-operation-child-" + suffix;

        write(permissions, List.of(
                relationship("organization", organizationId, "denied_operation", "operation", operationId),
                relationship("department", departmentId, "organization", "organization", organizationId),
                relationship("department", departmentId, "capability", "scope_capability", childCapabilityId),
                relationship("team", rootTeamId, "organization", "organization", organizationId),
                relationship("team", childTeamId, "parent", "team", rootTeamId),
                relationship("team", childTeamId, "operation_restriction", "scope_operation", childOperationId),
                relationship("scope_operation", childOperationId, "parent", "scope_operation", rootOperationId),
                relationship("scope_operation", rootOperationId, "denied_account", "account", accountId),
                relationship("scope_capability", childCapabilityId, "parent", "scope_capability", parentCapabilityId),
                relationship("scope_capability", parentCapabilityId, "grantee", "account", accountId),
                relationship("scope_capability", parentCapabilityId, "category_grantee", "account", accountId),
                relationship("scope_capability", parentCapabilityId, "scoped_grantee", "account", otherAccountId),
                relationship("scope_capability", parentCapabilityId, "responsibility_grantee", "account", otherAccountId),
                relationship("scope_capability", childCapabilityId, "responsibility_grantee", "account", accountId),
                relationship("scope_capability", childCapabilityId, "scoped_grantee", "account", accountId),
                relationship("scope_capability", otherCapabilityId, "scoped_grantee", "account", accountId)));
        try {
            require(permissions, "department", departmentId, "capability_grant", "account", accountId, true);
            require(permissions, "department", departmentId, "capability_grant", "account", otherAccountId, false);
            require(permissions, "scope_capability", childCapabilityId, "category_grant", "account", accountId, true);
            require(permissions, "scope_capability", childCapabilityId, "scoped_grant", "account", accountId, true);
            require(permissions, "scope_capability", parentCapabilityId, "responsibility_grant", "account", otherAccountId, true);
            require(permissions, "scope_capability", childCapabilityId, "scoped_grant", "account", otherAccountId, true);
            require(permissions, "scope_capability", childCapabilityId, "responsibility_grant", "account", otherAccountId, false);
            require(permissions, "scope_capability", childCapabilityId, "responsibility_grant", "account", accountId, true);
            require(permissions, "scope_capability", otherCapabilityId, "responsibility_grant", "account", accountId, false);
            require(permissions, "scope_capability", otherCapabilityId, "category_grant", "account", accountId, false);
            require(permissions, "scope_capability", otherCapabilityId, "scoped_grant", "account", accountId, true);
            require(permissions, "department", departmentId, "explicit_deny", "operation", operationId, true);
            require(permissions, "team", childTeamId, "explicit_deny", "operation", operationId, true);
            require(permissions, "team", childTeamId, "explicit_deny", "account", accountId, true);
            require(permissions, "team", childTeamId, "explicit_deny", "account", otherAccountId, false);
        } finally {
            delete(permissions, "team", childTeamId);
            delete(permissions, "team", rootTeamId);
            delete(permissions, "department", departmentId);
            delete(permissions, "organization", organizationId);
            delete(permissions, "scope_capability", childCapabilityId);
            delete(permissions, "scope_capability", parentCapabilityId);
            delete(permissions, "scope_capability", otherCapabilityId);
            delete(permissions, "scope_operation", childOperationId);
            delete(permissions, "scope_operation", rootOperationId);
        }
        require(permissions, "department", departmentId, "capability_grant", "account", accountId, false);
        require(permissions, "team", childTeamId, "explicit_deny", "operation", operationId, false);
        require(permissions, "team", childTeamId, "explicit_deny", "account", accountId, false);
    }

    /**
     * Proves content schema privacy and ancestor revocation using temporary graph-only fixtures.
     * No IAM user, session, membership record or business resource is provisioned.
     * @param permissions separate operator connection to the existing engine
     */
    private static void validateContentRelationships(PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions) {
        String organization = UUID.randomUUID().toString();
        String owner = UUID.randomUUID().toString();
        String employee = UUID.randomUUID().toString();
        String administrator = UUID.randomUUID().toString();
        String workspace = UUID.randomUUID() + "_r1";
        String directory = workspace + "_" + UUID.randomUUID();
        String file = workspace + "_" + UUID.randomUUID();
        String group = UUID.randomUUID().toString();
        Relationship liveParent = relationship("content_directory",directory,"live","organization",organization);
        Relationship publicAudience = relationship("content_file",file,"audience","organization",organization);
        try {
            write(permissions,List.of(
                    relationship("organization",organization,"account_member","account",owner),
                    relationship("organization",organization,"account_member","account",employee),
                    relationship("organization",organization,"account_member","account",administrator),
                    relationship("content_workspace",workspace,"organization","organization",organization),
                    relationship("content_workspace",workspace,"live","organization",organization),
                    relationship("content_workspace",workspace,"owner","account",owner),
                    relationship("content_directory",directory,"organization","organization",organization),
                    liveParent,relationship("content_directory",directory,"parent","content_workspace",workspace),
                    relationship("content_file",file,"organization","organization",organization),
                    relationship("content_file",file,"live","organization",organization),
                    relationship("content_file",file,"parent","content_directory",directory),
                    relationship("content_file",file,"owner","account",owner)));
            require(permissions,"content_file",file,"view","account",owner,true);
            require(permissions,"content_file",file,"edit","account",owner,true);
            require(permissions,"content_workspace",workspace,"view","account",administrator,false);
            require(permissions,"content_file",file,"view","account",employee,false);
            write(permissions,List.of(relationship("content_file",file,"viewer","account",employee)));
            require(permissions,"content_file",file,"view","account",employee,true);
            require(permissions,"content_file",file,"edit","account",employee,false);
            require(permissions,"content_workspace",workspace,"view","account",employee,false);
            require(permissions,"content_directory",directory,"view","account",employee,false);
            write(permissions,List.of(publicAudience));
            require(permissions,"content_file",file,"view","account",administrator,true);
            require(permissions,"content_file",file,"edit","account",administrator,false);
            remove(permissions,publicAudience);
            require(permissions,"content_file",file,"view","account",administrator,false);
            remove(permissions,liveParent);
            require(permissions,"content_file",file,"view","account",owner,false);
            require(permissions,"content_file",file,"view","account",employee,false);
            write(permissions,List.of(liveParent));
            require(permissions,"content_file",file,"view","account",employee,true);
            require(permissions,"content_workspace",workspace.replace("_r1","_r2"),"view","account",owner,false);
            for (String groupType : List.of("department", "team")) {
                Relationship audience = relationship("content_workspace",workspace,"audience",groupType,group);
                write(permissions,List.of(relationship(groupType,group,"account_member","account",administrator),audience));
                require(permissions,"content_workspace",workspace,"view","account",administrator,true);
                require(permissions,"content_workspace",workspace,"edit","account",administrator,true);
                remove(permissions,audience);
                require(permissions,"content_workspace",workspace,"view","account",administrator,false);
                delete(permissions,groupType,group);
            }
            delete(permissions,"organization",organization);
            require(permissions,"content_file",file,"view","account",employee,false);
            require(permissions,"content_file",file,"view","account",owner,false);
        } finally {
            delete(permissions,"content_file",file);
            delete(permissions,"content_directory",directory);
            delete(permissions,"content_workspace",workspace);
            delete(permissions,"organization",organization);
            delete(permissions,"department",group);
            delete(permissions,"team",group);
        }
    }

    /**
     * Exercises personal same-authority, exact-invitation and live-ancestor boundaries on isolated graph fixtures.
     * @param permissions separate operator connection; never an application credential
     */
    private static void validateIndividualRelationships(PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions) {
        String owner=UUID.randomUUID().toString(),recipient=UUID.randomUUID().toString(),outsider=UUID.randomUUID().toString();
        String workspace=UUID.randomUUID()+"_r1",directory=workspace+"_"+UUID.randomUUID(),file=workspace+"_"+UUID.randomUUID();
        String group=UUID.randomUUID().toString(),capability="a".repeat(64)+"_"+UUID.randomUUID(),other="b".repeat(64)+"_"+UUID.randomUUID();
        Relationship live=relationship("individual_content_directory",directory,"live","account","*");
        Relationship participant=relationship("individual_group",group,"participant","account",recipient);
        try {
            write(permissions,List.of(
                    relationship("individual_capability",capability,"category_grantee","account",owner),
                    relationship("individual_capability",other,"local_grantee","account",owner),
                    relationship("individual_content_workspace",workspace,"live","account","*"),
                    relationship("individual_content_workspace",workspace,"owner","account",owner),
                    live,relationship("individual_content_directory",directory,"parent","individual_content_workspace",workspace),
                    relationship("individual_content_file",file,"live","account","*"),
                    relationship("individual_content_file",file,"parent","individual_content_directory",directory),
                    relationship("individual_content_file",file,"owner","account",owner),
                    relationship("individual_content_file",file,"viewer","account",recipient)));
            require(permissions,"individual_capability",capability,"grant","account",owner,false);
            require(permissions,"individual_capability",other,"grant","account",owner,false);
            write(permissions,List.of(relationship("individual_capability",capability,"local_grantee","account",owner)));
            require(permissions,"individual_capability",capability,"grant","account",owner,true);
            require(permissions,"individual_capability",capability,"grant","account",recipient,false);
            require(permissions,"individual_content_file",file,"view","account",owner,true);
            require(permissions,"individual_content_file",file,"edit","account",owner,true);
            require(permissions,"individual_content_file",file,"view","account",recipient,true);
            require(permissions,"individual_content_file",file,"edit","account",recipient,false);
            require(permissions,"individual_content_workspace",workspace,"view","account",recipient,false);
            require(permissions,"individual_content_directory",directory,"view","account",recipient,false);
            require(permissions,"individual_content_file",file,"view","account",outsider,false);
            write(permissions,List.of(relationship("individual_content_file",file,"editor","account",recipient)));
            require(permissions,"individual_content_file",file,"edit","account",recipient,true);
            remove(permissions,live);
            require(permissions,"individual_content_file",file,"view","account",owner,false);
            require(permissions,"individual_content_file",file,"edit","account",recipient,false);
            write(permissions,List.of(live));
            require(permissions,"individual_content_file",file,"view","account",recipient,true);
            require(permissions,"individual_content_file",file.replace("_r1","_r2"),"view","account",owner,false);
            write(permissions,List.of(participant,relationship("individual_content_workspace",workspace,"audience","individual_group",group)));
            require(permissions,"individual_content_workspace",workspace,"view","account",recipient,true);
            require(permissions,"individual_content_workspace",workspace,"edit","account",recipient,true);
            remove(permissions,participant);
            require(permissions,"individual_content_workspace",workspace,"view","account",recipient,false);
            require(permissions,"individual_content_file",file,"view","account",recipient,true);
        } finally {
            delete(permissions,"individual_capability",capability);delete(permissions,"individual_capability",other);
            delete(permissions,"individual_content_file",file);delete(permissions,"individual_content_directory",directory);
            delete(permissions,"individual_content_workspace",workspace);delete(permissions,"individual_group",group);
        }
    }

    /** @param permissions operator connection @param relationship fixture edge to revoke exactly */
    private static void remove(PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions, Relationship relationship) {
        permissions.withDeadlineAfter(RPC_DEADLINE_MILLIS,TimeUnit.MILLISECONDS).writeRelationships(
                WriteRelationshipsRequest.newBuilder().addUpdates(RelationshipUpdate.newBuilder()
                        .setOperation(RelationshipUpdate.Operation.OPERATION_DELETE).setRelationship(relationship)).build());
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

    private static void write(PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions,
            List<Relationship> relationships) {
        WriteRelationshipsRequest.Builder request = WriteRelationshipsRequest.newBuilder();
        for (Relationship relationship : relationships) {
            request.addUpdates(RelationshipUpdate.newBuilder()
                    .setOperation(RelationshipUpdate.Operation.OPERATION_CREATE)
                    .setRelationship(relationship));
        }
        permissions.withDeadlineAfter(RPC_DEADLINE_MILLIS, TimeUnit.MILLISECONDS).writeRelationships(request.build());
    }

    private static void delete(PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions,
            String resourceType, String resourceId) {
        DeleteRelationshipsRequest request = DeleteRelationshipsRequest.newBuilder()
                .setRelationshipFilter(RelationshipFilter.newBuilder()
                        .setResourceType(resourceType).setOptionalResourceId(resourceId))
                .build();
        permissions.withDeadlineAfter(RPC_DEADLINE_MILLIS, TimeUnit.MILLISECONDS).deleteRelationships(request);
    }

    private static void require(PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions,
            String resourceType, String resourceId, String permission, String subjectType, String subjectId,
            boolean expected) {
        CheckPermissionRequest request = CheckPermissionRequest.newBuilder()
                .setConsistency(Consistency.newBuilder().setFullyConsistent(true))
                .setResource(ObjectReference.newBuilder().setObjectType(resourceType).setObjectId(resourceId))
                .setPermission(permission)
                .setSubject(SubjectReference.newBuilder().setObject(
                        ObjectReference.newBuilder().setObjectType(subjectType).setObjectId(subjectId)))
                .build();
        CheckPermissionResponse response = permissions.withDeadlineAfter(RPC_DEADLINE_MILLIS, TimeUnit.MILLISECONDS)
                .checkPermission(request);
        boolean allowed = response.getPermissionship() == CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION;
        if (allowed != expected) throw new IllegalStateException("SpiceDB schema relationship assertion failed.");
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException("Required operator configuration is missing: " + name);
        return value;
    }

    private static String host(String endpoint) {
        try {
            return java.net.URI.create("https://" + endpoint).getHost();
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("Invalid SpiceDB endpoint.");
        }
    }

    private static String schemaVersion(String schema) {
        if (schema.contains("Individual content v4")) return "individual_content_v4";
        if (schema.contains("Organization content v3")) return "organization_content_v3";
        return schema.contains("Phase-3 organization canary schema") ? "organization_v2" : "unknown";
    }
}
