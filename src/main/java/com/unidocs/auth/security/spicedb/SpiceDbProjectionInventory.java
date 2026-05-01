package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.Consistency;
import com.authzed.api.v1.Cursor;
import com.authzed.api.v1.PermissionsServiceGrpc;
import com.authzed.api.v1.ReadRelationshipsRequest;
import com.authzed.api.v1.ReadRelationshipsResponse;
import com.authzed.api.v1.Relationship;
import com.authzed.api.v1.RelationshipFilter;
import com.authzed.api.v1.SubjectFilter;
import com.authzed.api.v1.ZedToken;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/** Read-only, bounded organization inventory used exclusively by the explicit operator entry point. */
final class SpiceDbProjectionInventory {
    private static final int MAX_TUPLES=50_000;
    private static final int MAX_SCOPES=256;
    private static final int PAGE_SIZE=1000;
    private final PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions;
    private final Set<SpiceDbRelationship> actual=new HashSet<>();
    private ZedToken snapshot;

    /** @param permissions separately authenticated operator stub, never an application credential */
    SpiceDbProjectionInventory(PermissionsServiceGrpc.PermissionsServiceBlockingStub permissions) {
        this.permissions=permissions;
    }

    /**
     * Compares physical tenant relationships with a stable acknowledged-ledger export without issuing any write RPC.
     * @param manifest tenant UUID followed by source-owned SCOPE/type/UUID lines and five-field acknowledged tuples
     * @return number of exactly matching tuples
     * @throws IllegalArgumentException when the bounded manifest is malformed or crosses scope boundaries
     * @throws IllegalStateException when physical tuples differ or snapshot evidence is incomplete
     */
    int verify(List<String> manifest) {
        actual.clear();
        snapshot=null;
        if(manifest.isEmpty()||manifest.size()>MAX_TUPLES+1)throw new IllegalArgumentException("Invalid inventory manifest size.");
        UUID organization=UUID.fromString(manifest.getFirst());
        String root=organization.toString();
        Set<SpiceDbRelationship> expected=new HashSet<>();
        Set<Scope> scopes=new HashSet<>();
        Set<Scope> sourceScopes=new HashSet<>();
        scopes.add(new Scope("organization",root));
        for(String line:manifest.subList(1,manifest.size())) {
            String[] fields=line.split("\t",-1);
            if(fields.length==3&&fields[0].equals("SCOPE")&&Set.of("department","team").contains(fields[1])) {
                UUID.fromString(fields[2]);
                Scope scope=new Scope(fields[1],fields[2]);sourceScopes.add(scope);scopes.add(scope);
                continue;
            }
            if(fields.length!=5)throw new IllegalArgumentException("Invalid inventory manifest tuple.");
            SpiceDbRelationship tuple=new SpiceDbRelationship(fields[0],fields[1],fields[2],fields[3],fields[4]);
            if(!Set.of("organization","department","team","scope_capability","scope_operation").contains(tuple.resourceType())
                    || !expected.add(tuple))throw new IllegalArgumentException("Invalid or duplicate inventory resource.");
            if(tuple.resourceType().equals("organization")&&!tuple.resourceId().equals(root))
                throw new IllegalArgumentException("Inventory contains another organization.");
            if(Set.of("team","department").contains(tuple.resourceType())) {
                UUID.fromString(tuple.resourceId());
                scopes.add(new Scope(tuple.resourceType(),tuple.resourceId()));
            }
        }
        Set<String> scopeIds=new HashSet<>();
        for(Scope scope:scopes) {
            if(!scope.type().equals("organization")&&!sourceScopes.contains(scope)&&!expected.contains(new SpiceDbRelationship(scope.type(),scope.id(),
                    "organization","organization",root)))throw new IllegalArgumentException("Inventory group lacks its tenant anchor.");
            if(!scopeIds.add(compact(scope.id())))throw new IllegalArgumentException("Inventory contains conflicting scope types.");
        }
        for(SpiceDbRelationship tuple:expected)if(Set.of("scope_capability","scope_operation").contains(tuple.resourceType())
                && (!tuple.resourceId().matches("[0-9a-f]{64}")||scopeIds.stream().noneMatch(tuple.resourceId()::startsWith)))
            throw new IllegalArgumentException("Inventory capability belongs to an unknown scope.");
        if(scopes.size()>MAX_SCOPES)throw new IllegalArgumentException("Inventory scope bound exceeded.");
        read(RelationshipFilter.newBuilder().setResourceType("organization").setOptionalResourceId(root).build());
        if(snapshot==null)throw new IllegalStateException("Inventory requires an existing organization snapshot.");
        // Discover graph-only groups as well as source-ledger groups so stale anchored objects cannot hide.
        for(String type:List.of("department","team"))read(RelationshipFilter.newBuilder().setResourceType(type)
                .setOptionalSubjectFilter(SubjectFilter.newBuilder().setSubjectType("organization").setOptionalSubjectId(root)).build());
        for(SpiceDbRelationship tuple:actual)if(Set.of("department","team").contains(tuple.resourceType()))
            scopes.add(new Scope(tuple.resourceType(),tuple.resourceId()));
        if(scopes.size()>MAX_SCOPES)throw new IllegalStateException("Physical inventory scope bound exceeded.");
        for(Scope scope:scopes) {
            if(!scope.type().equals("organization"))read(RelationshipFilter.newBuilder().setResourceType(scope.type()).setOptionalResourceId(scope.id()).build());
            for(String type:List.of("scope_capability","scope_operation"))
                read(RelationshipFilter.newBuilder().setResourceType(type).setOptionalResourceIdPrefix(compact(scope.id())).build());
        }
        if(!actual.equals(expected))throw new IllegalStateException("Physical organization tuples differ from the acknowledged ledger.");
        return actual.size();
    }

    /**
     * Verifies Document-owned generations without giving the application a relationship-read credential.
     * @param manifest tenant UUID, WORKSPACE/UUID source declarations and five-column acknowledged tuples
     * @return exact number of physical content tuples at a single graph snapshot
     * @throws IllegalArgumentException when the manifest is malformed or crosses an owning workspace boundary
     * @throws IllegalStateException when physical content differs or complete snapshot evidence is unavailable
     */
    int verifyContent(List<String> manifest) {
        actual.clear();
        snapshot=null;
        if(manifest.isEmpty() || manifest.size()>MAX_TUPLES+MAX_SCOPES+1)
            throw new IllegalArgumentException("Invalid content inventory size.");
        String organization=UUID.fromString(manifest.getFirst()).toString();
        Set<String> workspaces=new HashSet<>();
        Set<SpiceDbRelationship> expected=new HashSet<>();
        Set<String> types=Set.of("content_workspace","content_directory","content_file");
        for(String line:manifest.subList(1,manifest.size())) {
            String[] fields=line.split("\t",-1);
            if(fields.length==2 && fields[0].equals("WORKSPACE")) {
                if(!workspaces.add(UUID.fromString(fields[1]).toString()))
                    throw new IllegalArgumentException("Duplicate content workspace.");
            } else {
                if(fields.length!=5 || !types.contains(fields[0]))
                    throw new IllegalArgumentException("Invalid content inventory tuple.");
                SpiceDbRelationship tuple=new SpiceDbRelationship(fields[0],fields[1],fields[2],fields[3],fields[4]);
                if(!expected.add(tuple))throw new IllegalArgumentException("Duplicate content inventory tuple.");
            }
        }
        if(workspaces.isEmpty() || workspaces.size()>MAX_SCOPES || expected.size()>MAX_TUPLES)
            throw new IllegalArgumentException("Content inventory bound exceeded.");
        for(SpiceDbRelationship tuple:expected) {
            String root=contentRoot(tuple.resourceId());
            if(!workspaces.contains(root) || tuple.resourceType().equals("content_workspace")
                    && !tuple.resourceId().matches(root+"_r[1-9][0-9]*"))
                throw new IllegalArgumentException("Content tuple has no declared owning workspace.");
            if(tuple.subjectType().equals("organization") && !tuple.subjectId().equals(organization))
                throw new IllegalArgumentException("Content tuple crosses tenants.");
            if(types.contains(tuple.subjectType()) && (!contentRoot(tuple.subjectId()).equals(root)
                    || !contentGeneration(tuple.resourceId()).equals(contentGeneration(tuple.subjectId()))))
                throw new IllegalArgumentException("Content tuple crosses source generations.");
        }
        // The existing IAM anchor supplies a snapshot even when every content collection is empty.
        read(RelationshipFilter.newBuilder().setResourceType("organization").setOptionalResourceId(organization).build());
        if(snapshot==null)throw new IllegalStateException("Content inventory requires the current tenant anchor.");
        actual.clear();
        for(String type:types) read(RelationshipFilter.newBuilder().setResourceType(type).setOptionalSubjectFilter(
                SubjectFilter.newBuilder().setSubjectType("organization").setOptionalSubjectId(organization)).build());
        for(SpiceDbRelationship tuple:actual)workspaces.add(contentRoot(tuple.resourceId()));
        if(workspaces.size()>MAX_SCOPES)throw new IllegalStateException("Physical content workspace bound exceeded.");
        for(String workspace:workspaces)for(String type:types)
            read(RelationshipFilter.newBuilder().setResourceType(type).setOptionalResourceIdPrefix(workspace+"_r").build());
        if(!actual.equals(expected))throw new IllegalStateException("Physical content tuples differ from the acknowledged ledger.");
        return actual.size();
    }

    /**
     * Verifies explicitly declared basic resource and immutable IAM generations at one fresh snapshot.
     * @param manifest INDIVIDUAL header, WORKSPACE/CAPABILITY/GROUP declarations and five-column exact tuples
     * @return physical tuple count without writes or application read credentials
     * @throws IllegalArgumentException for malformed, unbounded or undeclared scopes
     * @throws IllegalStateException when physical state or revision evidence differs
     */
    int verifyIndividual(List<String> manifest) {
        actual.clear();snapshot=null;
        if(manifest.isEmpty() || !manifest.getFirst().equals("INDIVIDUAL") || manifest.size()>MAX_TUPLES+MAX_SCOPES+1)
            throw new IllegalArgumentException("Invalid personal inventory.");
        Set<Scope> scopes=new HashSet<>();Set<String> workspaces=new HashSet<>();Set<SpiceDbRelationship> expected=new HashSet<>();
        Set<String> content=Set.of("individual_content_workspace","individual_content_directory","individual_content_file");
        for(String line:manifest.subList(1,manifest.size())) {
            String[] fields=line.split("\t",-1);
            if(fields.length==2) {
                switch(fields[0]) {
                    case "WORKSPACE" -> workspaces.add(UUID.fromString(fields[1]).toString());
                    case "CAPABILITY" -> {
                        if(!fields[1].matches("[0-9a-f]{64}_[0-9a-f-]{36}"))throw new IllegalArgumentException("Invalid personal capability.");
                        scopes.add(new Scope("individual_capability",fields[1]));
                    }
                    case "GROUP" -> scopes.add(new Scope("individual_group",UUID.fromString(fields[1]).toString()));
                    default -> throw new IllegalArgumentException("Invalid personal scope declaration.");
                }
            } else if(fields.length==5) {
                SpiceDbRelationship tuple=new SpiceDbRelationship(fields[0],fields[1],fields[2],fields[3],fields[4]);
                if(!expected.add(tuple))throw new IllegalArgumentException("Duplicate personal inventory tuple.");
                com.authzed.api.v1.WriteRelationshipsRequest request=com.authzed.api.v1.WriteRelationshipsRequest.newBuilder()
                        .addUpdates(tuple.update(com.authzed.api.v1.RelationshipUpdate.Operation.OPERATION_TOUCH)).build();
                if(content.contains(tuple.resourceType()))SpiceDbApiGateway.validateDocumentWrite(request);
                else if(Set.of("individual_capability","individual_group").contains(tuple.resourceType()))SpiceDbApiGateway.validateWrite(request);
                else throw new IllegalArgumentException("Unsupported personal inventory type.");
            } else throw new IllegalArgumentException("Invalid personal inventory row.");
        }
        if(scopes.size()+workspaces.size()>MAX_SCOPES || expected.size()>MAX_TUPLES || expected.isEmpty())
            throw new IllegalArgumentException("Personal inventory bound exceeded or empty.");
        for(SpiceDbRelationship tuple:expected) {
            if(content.contains(tuple.resourceType())?!workspaces.contains(contentRoot(tuple.resourceId())):
                    !scopes.contains(new Scope(tuple.resourceType(),tuple.resourceId())))
                throw new IllegalArgumentException("Undeclared personal inventory scope.");
        }
        SpiceDbRelationship anchor=expected.iterator().next();
        com.authzed.api.v1.CheckPermissionResponse fresh=permissions.withDeadlineAfter(10_000,TimeUnit.MILLISECONDS).checkPermission(
                com.authzed.api.v1.CheckPermissionRequest.newBuilder().setResource(com.authzed.api.v1.ObjectReference.newBuilder()
                        .setObjectType(anchor.resourceType()).setObjectId(anchor.resourceId()))
                        .setPermission(content.contains(anchor.resourceType())?"available":anchor.resourceType().equals("individual_group")?"member":"grant")
                        .setSubject(com.authzed.api.v1.SubjectReference.newBuilder().setObject(com.authzed.api.v1.ObjectReference.newBuilder()
                                .setObjectType("account").setObjectId("00000000-0000-0000-0000-000000000000")))
                        .setConsistency(Consistency.newBuilder().setFullyConsistent(true)).build());
        if(!fresh.hasCheckedAt() || fresh.getCheckedAt().getToken().isBlank())throw new IllegalStateException("Missing inventory snapshot.");
        snapshot=fresh.getCheckedAt();
        for(Scope scope:scopes)read(RelationshipFilter.newBuilder().setResourceType(scope.type()).setOptionalResourceId(scope.id()).build());
        for(String workspace:workspaces)for(String type:content)
            read(RelationshipFilter.newBuilder().setResourceType(type).setOptionalResourceIdPrefix(workspace+"_r").build());
        if(!actual.equals(expected))throw new IllegalStateException("Physical personal tuples differ from committed intent.");
        return actual.size();
    }

    /** @param resource generation-qualified resource ID @return canonical owning workspace UUID */
    private static String contentRoot(String resource) {
        if(!resource.matches("[0-9a-f-]{36}_r[1-9][0-9]*(_[0-9a-f-]{36})?"))
            throw new IllegalArgumentException("Invalid generation-qualified content identity.");
        String root=resource.substring(0,36);
        if(!UUID.fromString(root).toString().equals(root))throw new IllegalArgumentException("Invalid content workspace.");
        if(resource.indexOf('_',38)>=0)UUID.fromString(resource.substring(resource.indexOf('_',38)+1));
        return root;
    }

    /** @param resource validated resource ID @return workspace and generation, without an optional child ID */
    private static String contentGeneration(String resource) {
        contentRoot(resource);
        int child=resource.indexOf('_',38);
        return child<0?resource:resource.substring(0,child);
    }

    /**
     * Reads bounded physical tuples, pinning every stream and response to the first authoritative revision.
     * @param filter server-constructed organization, group or capability-prefix filter
     * @throws IllegalStateException when evidence is incomplete or exceeds its bounded contract
     */
    private void read(RelationshipFilter filter) {
        Cursor cursor=null;
        Set<String> cursors=new HashSet<>();
        int total=0;
        while(true) {
            ReadRelationshipsRequest.Builder request=ReadRelationshipsRequest.newBuilder().setRelationshipFilter(filter)
                    .setOptionalLimit(PAGE_SIZE).setConsistency(snapshot==null?Consistency.newBuilder().setFullyConsistent(true).build()
                            :Consistency.newBuilder().setAtExactSnapshot(snapshot).build());
            if(cursor!=null)request.setOptionalCursor(cursor);
            Iterator<ReadRelationshipsResponse> rows=permissions.withDeadlineAfter(10_000,TimeUnit.MILLISECONDS).readRelationships(request.build());
            int count=0;
            Cursor last=null;
            while(rows.hasNext()) {
                ReadRelationshipsResponse row=rows.next();
                if(++count>PAGE_SIZE||++total>MAX_TUPLES||!row.hasReadAt()||row.getReadAt().getToken().isBlank())
                    throw new IllegalStateException("Inventory response is incomplete or exceeds its bound.");
                if(snapshot==null)snapshot=row.getReadAt();
                if(!snapshot.equals(row.getReadAt()))throw new IllegalStateException("Inventory streams changed revision.");
                Relationship tuple=row.getRelationship();
                if(tuple.hasOptionalCaveat()||tuple.hasOptionalExpiresAt()||!tuple.getSubject().getOptionalRelation().isEmpty())
                    throw new IllegalStateException("Inventory found unsupported conditional or expiring tuples.");
                actual.add(new SpiceDbRelationship(tuple.getResource().getObjectType(),tuple.getResource().getObjectId(),
                        tuple.getRelation(),tuple.getSubject().getObject().getObjectType(),tuple.getSubject().getObject().getObjectId()));
                if(actual.size()>MAX_TUPLES)throw new IllegalStateException("Physical inventory tuple bound exceeded.");
                last=row.getAfterResultCursor();
            }
            if(count<PAGE_SIZE)return;
            // A full page is not proof of exhaustion; only an advancing opaque cursor can continue safely.
            if(last==null||last.getToken().isBlank()||!cursors.add(last.getToken()))
                throw new IllegalStateException("Inventory pagination cannot establish complete physical state.");
            cursor=last;
        }
    }

    /** @param id scope UUID @return canonical compact capability prefix */
    private static String compact(String id) { return UUID.fromString(id).toString().replace("-",""); }
    private record Scope(String type,String id) { }
}
