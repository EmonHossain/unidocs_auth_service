package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class SpiceDbProjectionInventoryTests {
    /** @param orphan whether an unacknowledged older basic generation remains remotely */
    @ParameterizedTest @ValueSource(booleans={false,true})
    void personalInventoryPinsAllScopesAndDetectsStaleGenerations(boolean orphan) {
        String workspace=UUID.randomUUID().toString(),capability="a".repeat(64)+"_"+UUID.randomUUID();
        SpiceDbRelationship live=new SpiceDbRelationship("individual_content_workspace",workspace+"_r2","live","account","*");
        SpiceDbRelationship grant=new SpiceDbRelationship("individual_capability",capability,"category_grantee","account",account);
        List<ReadRelationshipsResponse> rows=new ArrayList<>(List.of(row(live,revision),row(grant,revision)));
        if(orphan)rows.add(row(new SpiceDbRelationship("individual_content_file",workspace+"_r1_"+UUID.randomUUID(),"viewer","account",account),revision));
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub=stub(rows);
        when(stub.checkPermission(any())).thenReturn(CheckPermissionResponse.newBuilder().setCheckedAt(revision)
                .setPermissionship(CheckPermissionResponse.Permissionship.PERMISSIONSHIP_NO_PERMISSION).build());
        List<String> manifest=List.of("INDIVIDUAL","WORKSPACE\t"+workspace,"CAPABILITY\t"+capability,
                String.join("\t",live.resourceType(),live.resourceId(),live.relation(),live.subjectType(),live.subjectId()),
                String.join("\t",grant.resourceType(),grant.resourceId(),grant.relation(),grant.subjectType(),grant.subjectId()));
        SpiceDbProjectionInventory inventory=new SpiceDbProjectionInventory(stub);
        if(orphan)assertThrows(IllegalStateException.class,()->inventory.verifyIndividual(manifest));else assertEquals(2,inventory.verifyIndividual(manifest));
        org.mockito.ArgumentCaptor<ReadRelationshipsRequest> reads=org.mockito.ArgumentCaptor.forClass(ReadRelationshipsRequest.class);
        verify(stub,atLeastOnce()).readRelationships(reads.capture());
        assertTrue(reads.getAllValues().stream().allMatch(request->request.getConsistency().getAtExactSnapshot().equals(revision)));
        verify(stub,never()).writeRelationships(any());verify(stub,never()).deleteRelationships(any());
    }

    /** Invalid or undeclared basic scopes cannot reach the privileged read client. */
    @Test void personalInventoryRejectsUndeclaredScopesBeforeRpc() {
        String workspace=UUID.randomUUID().toString();PermissionsServiceGrpc.PermissionsServiceBlockingStub stub=mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        assertThrows(IllegalArgumentException.class,()->new SpiceDbProjectionInventory(stub).verifyIndividual(List.of("INDIVIDUAL",
                "individual_content_workspace\t"+workspace+"_r1\towner\taccount\t"+account)));
        assertThrows(IllegalArgumentException.class,()->new SpiceDbProjectionInventory(stub).verifyIndividual(List.of("INDIVIDUAL","WORKSPACE\t"+workspace,
                "content_workspace\t"+workspace+"_r1\towner\taccount\t"+account)));
        verifyNoInteractions(stub);
    }
    /**
     * Inspects all source generations, including an orphan grant lacking its tenant anchor.
     * @param orphan whether an unacknowledged old-generation grant survives physically
     */
    @ParameterizedTest @ValueSource(booleans={false,true})
    void contentInventoryPinsSnapshotAndDetectsUnanchoredOldGenerations(boolean orphan) {
        String workspace=UUID.randomUUID().toString();
        SpiceDbRelationship anchor=new SpiceDbRelationship("content_workspace",workspace+"_r2","organization","organization",organization);
        SpiceDbRelationship owner=new SpiceDbRelationship("content_workspace",workspace+"_r2","owner","account",account);
        SpiceDbRelationship old=new SpiceDbRelationship("content_file",workspace+"_r1_"+UUID.randomUUID(),"viewer","account",account);
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub=stub(List.of());
        List<ReadRelationshipsRequest> reads=new ArrayList<>();
        doAnswer(call->{
            ReadRelationshipsRequest request=call.getArgument(0);reads.add(request);
            RelationshipFilter filter=request.getRelationshipFilter();
            if(filter.getResourceType().equals("organization"))return List.of(row(member,revision)).iterator();
            if(filter.getResourceType().equals("content_workspace"))
                return (filter.hasOptionalSubjectFilter()?List.of(row(anchor,revision)):
                        List.of(row(anchor,revision),row(owner,revision))).iterator();
            if(orphan && filter.getResourceType().equals("content_file") && !filter.getOptionalResourceIdPrefix().isEmpty())
                return List.of(row(old,revision)).iterator();
            return List.<ReadRelationshipsResponse>of().iterator();
        }).when(stub).readRelationships(any());
        List<String> manifest=List.of(organization,"WORKSPACE\t"+workspace,
                String.join("\t",anchor.resourceType(),anchor.resourceId(),anchor.relation(),anchor.subjectType(),anchor.subjectId()),
                String.join("\t",owner.resourceType(),owner.resourceId(),owner.relation(),owner.subjectType(),owner.subjectId()));
        SpiceDbProjectionInventory inventory=new SpiceDbProjectionInventory(stub);
        if(orphan)assertThrows(IllegalStateException.class,()->inventory.verifyContent(manifest));
        else assertEquals(2,inventory.verifyContent(manifest));
        assertTrue(reads.getFirst().getConsistency().getFullyConsistent());
        for(ReadRelationshipsRequest request:reads.subList(1,reads.size()))
            assertEquals(revision,request.getConsistency().getAtExactSnapshot());
        verify(stub,never()).writeRelationships(any());
        verify(stub,never()).deleteRelationships(any());
    }

    /** @param mismatch invalid content manifest boundary */
    @ParameterizedTest @ValueSource(strings={"tenant","workspace","generation","duplicate","malformed"})
    void contentManifestCannotCrossOwningBoundaries(String mismatch) {
        String workspace=UUID.randomUUID().toString(),other=UUID.randomUUID().toString();
        List<String> manifest=new ArrayList<>(List.of(organization,"WORKSPACE\t"+workspace));
        String tuple="content_file\t"+(mismatch.equals("workspace")?other:workspace)+"_r2_"+UUID.randomUUID()
                +"\tparent\tcontent_workspace\t"+workspace+(mismatch.equals("generation")?"_r1":"_r2");
        if(mismatch.equals("tenant"))tuple="content_workspace\t"+workspace+"_r2\torganization\torganization\t"+other;
        if(mismatch.equals("malformed"))tuple="content_workspace\tinvalid\towner\taccount\t"+account;
        manifest.add(tuple);
        if(mismatch.equals("duplicate"))manifest.add(tuple);
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub=mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        assertThrows(IllegalArgumentException.class,()->new SpiceDbProjectionInventory(stub).verifyContent(manifest));
        verifyNoInteractions(stub);
    }

    private final String organization=UUID.randomUUID().toString();
    private final String account=UUID.randomUUID().toString();
    private final String capability=organization.replace("-","")+UUID.randomUUID().toString().replace("-","");
    private final SpiceDbRelationship member=new SpiceDbRelationship("organization",organization,"account_member","account",account);
    private final ZedToken revision=ZedToken.newBuilder().setToken("opaque-test-snapshot").build();

    /** Matches exact tuples, pins subsequent reads and never invokes a mutating permissions RPC. */
    @Test void inventoryPinsEveryReadAndIssuesNoWrites() {
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub=stub(List.of(row(member,revision)));
        List<ReadRelationshipsRequest> reads=new ArrayList<>();
        doAnswer(call->{
            ReadRelationshipsRequest request=call.getArgument(0);reads.add(request);
            return request.getRelationshipFilter().getResourceType().equals("organization")
                    ?List.of(row(member,revision)).iterator():List.<ReadRelationshipsResponse>of().iterator();
        }).when(stub).readRelationships(any());
        assertEquals(1,new SpiceDbProjectionInventory(stub).verify(manifest(member)));
        assertTrue(reads.getFirst().getConsistency().getFullyConsistent());
        assertEquals(5,reads.size());
        for(ReadRelationshipsRequest request:reads.subList(1,reads.size()))
            assertEquals(revision,request.getConsistency().getAtExactSnapshot());
        verify(stub,never()).writeRelationships(any());
        verify(stub,never()).deleteRelationships(any());
    }

    /** An orphaned physical capability must fail even when every acknowledged tuple is present. */
    @Test void extraPhysicalCapabilityFailsExactParity() {
        SpiceDbRelationship extra=new SpiceDbRelationship("scope_capability",capability,"scoped_grantee","account",account);
        assertThrows(IllegalStateException.class,()->new SpiceDbProjectionInventory(stub(List.of(row(member,revision),row(extra,revision))))
                .verify(manifest(member)));
    }

    /** An acknowledged grant missing from physical storage must not be treated as complete projection. */
    @Test void missingPhysicalGrantFailsExactParity() {
        SpiceDbRelationship missing=new SpiceDbRelationship("scope_capability",capability,"scoped_grantee","account",account);
        assertThrows(IllegalStateException.class,()->new SpiceDbProjectionInventory(stub(List.of(row(member,revision))))
                .verify(manifest(member,missing)));
    }

    /** Historical source-owned scopes remain inspected even when every organization anchor was deleted remotely. */
    @Test void sourceRosterFindsUnanchoredOrphanCapability() {
        String retired=UUID.randomUUID().toString();
        SpiceDbRelationship orphan=new SpiceDbRelationship("scope_capability",retired.replace("-","")
                +UUID.randomUUID().toString().replace("-",""),"scoped_grantee","account",account);
        List<String> manifest=manifest(member);manifest.add("SCOPE\tteam\t"+retired);
        assertThrows(IllegalStateException.class,()->new SpiceDbProjectionInventory(stub(List.of(row(member,revision),row(orphan,revision))))
                .verify(manifest));
    }

    /** Traverses the server's 1,000-row bound with an opaque cursor at the original exact revision. */
    @Test void inventoryPaginatesAtOneSnapshotWithoutTruncatingPhysicalState() {
        List<SpiceDbRelationship> tuples=new ArrayList<>();
        for(int index=0;index<1001;index++)tuples.add(new SpiceDbRelationship("organization",organization,"account_member","account",UUID.randomUUID().toString()));
        List<ReadRelationshipsRequest> reads=new ArrayList<>();
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub=mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        when(stub.withDeadlineAfter(anyLong(),any())).thenReturn(stub);
        when(stub.readRelationships(any())).thenAnswer(call->{
            ReadRelationshipsRequest request=call.getArgument(0);reads.add(request);
            assertEquals(1000,request.getOptionalLimit());
            if(!request.getRelationshipFilter().getResourceType().equals("organization"))return List.<ReadRelationshipsResponse>of().iterator();
            if(request.hasOptionalCursor()) {
                assertEquals("page-one",request.getOptionalCursor().getToken());
                assertEquals(revision,request.getConsistency().getAtExactSnapshot());
                return List.of(row(tuples.getLast(),revision)).iterator();
            }
            List<ReadRelationshipsResponse> first=new ArrayList<>();
            for(SpiceDbRelationship tuple:tuples.subList(0,1000))first.add(row(tuple,revision).toBuilder()
                    .setAfterResultCursor(Cursor.newBuilder().setToken("page-one")).build());
            return first.iterator();
        });
        assertEquals(1001,new SpiceDbProjectionInventory(stub).verify(manifest(tuples.toArray(SpiceDbRelationship[]::new))));
        assertEquals(6,reads.size());
    }

    /** @param kind missing or non-advancing cursor on a full page */
    @ParameterizedTest @ValueSource(strings={"MISSING_CURSOR","REPEATED_CURSOR"})
    void fullPagesCannotSilentlyHideUnknownPhysicalTuples(String kind) {
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub=mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        when(stub.withDeadlineAfter(anyLong(),any())).thenReturn(stub);
        ReadRelationshipsResponse.Builder value=row(member,revision).toBuilder();
        if(kind.equals("REPEATED_CURSOR"))value.setAfterResultCursor(Cursor.newBuilder().setToken("unchanged"));
        when(stub.readRelationships(any())).thenAnswer(call->java.util.Collections.nCopies(1000,value.build()).iterator());
        assertThrows(IllegalStateException.class,()->new SpiceDbProjectionInventory(stub).verify(manifest(member)));
    }

    /**
     * Rejects incomplete, cross-revision and conditional physical evidence.
     * @param kind invalid response variant
     */
    @ParameterizedTest @ValueSource(strings={"MISSING_REVISION","OTHER_REVISION","CAVEAT","EXPIRATION","SUBJECT_RELATION"})
    void invalidPhysicalEvidenceFailsClosed(String kind) {
        SpiceDbRelationship tuple=new SpiceDbRelationship("scope_capability",capability,"scoped_grantee","account",account);
        ReadRelationshipsResponse.Builder response=row(tuple,revision).toBuilder();
        if(kind.equals("MISSING_REVISION"))response.clearReadAt();
        if(kind.equals("OTHER_REVISION"))response.setReadAt(ZedToken.newBuilder().setToken("different-test-snapshot"));
        if(kind.equals("CAVEAT"))response.getRelationshipBuilder().setOptionalCaveat(ContextualizedCaveat.newBuilder().setCaveatName("unsupported"));
        if(kind.equals("EXPIRATION"))response.getRelationshipBuilder().setOptionalExpiresAt(com.google.protobuf.Timestamp.newBuilder().setSeconds(1));
        if(kind.equals("SUBJECT_RELATION"))response.getRelationshipBuilder().getSubjectBuilder().setOptionalRelation("member");
        assertThrows(IllegalStateException.class,()->new SpiceDbProjectionInventory(stub(List.of(row(member,revision),response.build())))
                .verify(manifest(member,tuple)));
    }

    /** Rejects another tenant or unanchored scope before any operator RPC. */
    @Test void manifestCannotSelectAnotherTenantOrUnanchoredScope() {
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub=mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        SpiceDbRelationship foreign=new SpiceDbRelationship("organization",UUID.randomUUID().toString(),"account_member","account",account);
        assertThrows(IllegalArgumentException.class,()->new SpiceDbProjectionInventory(stub).verify(manifest(member,foreign)));
        SpiceDbRelationship unanchored=new SpiceDbRelationship("team",UUID.randomUUID().toString(),"account_member","account",account);
        assertThrows(IllegalArgumentException.class,()->new SpiceDbProjectionInventory(stub).verify(manifest(member,unanchored)));
        verifyNoInteractions(stub);
    }

    /** @param tuples expected relationships @return bounded TSV manifest with one tenant header */
    private List<String> manifest(SpiceDbRelationship... tuples) {
        List<String> lines=new ArrayList<>();lines.add(organization);
        for(SpiceDbRelationship tuple:tuples)lines.add(String.join("\t",tuple.resourceType(),tuple.resourceId(),tuple.relation(),tuple.subjectType(),tuple.subjectId()));
        return lines;
    }

    /** @param tuple physical tuple @param token pinned revision @return physical read response */
    private ReadRelationshipsResponse row(SpiceDbRelationship tuple,ZedToken token) {
        return ReadRelationshipsResponse.newBuilder().setReadAt(token)
                .setRelationship(tuple.update(RelationshipUpdate.Operation.OPERATION_TOUCH).getRelationship()).build();
    }

    /** @param rows mock physical storage @return stub applying the server's resource/id/prefix filters */
    private PermissionsServiceGrpc.PermissionsServiceBlockingStub stub(List<ReadRelationshipsResponse> rows) {
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub=mock(PermissionsServiceGrpc.PermissionsServiceBlockingStub.class);
        when(stub.withDeadlineAfter(anyLong(),any())).thenReturn(stub);
        when(stub.readRelationships(any())).thenAnswer(call->{
            RelationshipFilter filter=((ReadRelationshipsRequest)call.getArgument(0)).getRelationshipFilter();
            return rows.stream().filter(row->{
                ObjectReference resource=row.getRelationship().getResource();
                return resource.getObjectType().equals(filter.getResourceType())
                        && (filter.getOptionalResourceId().isEmpty()||filter.getOptionalResourceId().equals(resource.getObjectId()))
                        && (filter.getOptionalResourceIdPrefix().isEmpty()||resource.getObjectId().startsWith(filter.getOptionalResourceIdPrefix()));
            }).iterator();
        });
        return stub;
    }
}
