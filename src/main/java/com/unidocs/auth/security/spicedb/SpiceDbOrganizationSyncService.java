package com.unidocs.auth.security.spicedb;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** MySQL-authoritative organization snapshot, durable fence and exact relationship ledger. */
final class SpiceDbOrganizationSyncService {
    private static final int MAX_GROUP_DEPTH = 32;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final TransactionTemplate snapshotTransactions;
    private final SpiceDbOrganizationSyncProperties properties;

    /**
     * Configures short acknowledgement transactions and a separate coherent snapshot transaction.
     * @param jdbc owning Auth database access
     * @param manager transaction manager for the same data source
     * @param properties bounded synchronization settings
     */
    SpiceDbOrganizationSyncService(JdbcTemplate jdbc, PlatformTransactionManager manager,
            SpiceDbOrganizationSyncProperties properties) {
        this.jdbc = jdbc;
        this.tx = new TransactionTemplate(manager);
        this.snapshotTransactions = new TransactionTemplate(manager);
        this.snapshotTransactions.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        this.snapshotTransactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.properties = properties;
    }

    List<UUID> claimOrganizationsForSync(UUID leaseOwner, Instant now) {
        return tx.execute(status -> {
            List<byte[]> ids = jdbc.query("""
                    SELECT organization_id FROM spicedb_organization_sync_state
                    WHERE available_at<=? AND (sync_status='PENDING'
                        OR (next_boundary_at IS NOT NULL AND next_boundary_at<=?))
                      AND (lease_until IS NULL OR lease_until<=?)
                    ORDER BY available_at, organization_id LIMIT ? FOR UPDATE SKIP LOCKED
                    """, (rs, row) -> rs.getBytes(1), Timestamp.from(now), Timestamp.from(now),
                    Timestamp.from(now), properties.claimLimit());
            List<UUID> result = new ArrayList<>(ids.size());
            for (byte[] id : ids) {
                jdbc.update("UPDATE spicedb_organization_sync_state SET lease_owner=?,lease_until=?,sync_status='PENDING',updated_at=? WHERE organization_id=?",
                        bytes(leaseOwner), Timestamp.from(now.plusSeconds(properties.leaseSeconds())), Timestamp.from(now), id);
                result.add(uuid(id));
            }
            return result;
        });
    }

    int backfillMissingOrganizations(Instant now) {
        return tx.execute(status -> jdbc.update("""
            INSERT INTO spicedb_organization_sync_state(organization_id,required_revision,applied_revision,required_source_version,
                applied_source_version,sync_status,available_at,created_at,updated_at)
            SELECT o.id,1,0,o.authorization_version,0,'PENDING',?,?,? FROM organization o
            LEFT JOIN spicedb_organization_sync_state s ON s.organization_id=o.id
            WHERE s.organization_id IS NULL ORDER BY o.id LIMIT ?
            """,Timestamp.from(now),Timestamp.from(now),Timestamp.from(now),properties.claimLimit()));
    }

    /**
     * Holds a connection-owned advisory lock across snapshot preparation, remote writes and acknowledgement.
     * @param organization projected organization
     * @param leaseOwner current worker lease
     * @param relationshipWriter bounded gateway writer
     * @param now snapshot evaluation time
     * @throws IllegalStateException when invoked inside a SQL transaction
     */
    void synchronizeOrganization(UUID organization, UUID leaseOwner,
            SpiceDbRelationshipWriter relationshipWriter, Instant now) {
        requireOutsideTransaction();
        jdbc.execute((ConnectionCallback<Void>) connection -> {
            String lockName = "spicedb-org-" + organization.toString().replace("-", "");
            try (PreparedStatement statement = connection.prepareStatement("SELECT GET_LOCK(?, 0)")) {
                statement.setString(1, lockName);
                try (ResultSet rs = statement.executeQuery()) {
                    if (!rs.next() || rs.getInt(1) != 1) return null;
                }
            }
            try {
                synchronizeOrganizationLocked(organization, leaseOwner, relationshipWriter, now);
            } finally {
                try (PreparedStatement statement = connection.prepareStatement("SELECT RELEASE_LOCK(?)")) {
                    statement.setString(1, lockName);
                    statement.execute();
                }
            }
            return null;
        });
    }

    void recordSyncFailure(UUID organization, UUID leaseOwner, Instant now, String errorCode) {
        scheduleRetry(organization, leaseOwner, now, errorCode);
    }

    /**
     * Captures source facts and their exact revision in one repeatable-read transaction before graph RPCs.
     * @param organization advisory-locked organization
     * @param leaseOwner worker lease identity
     * @param relationshipWriter bounded gateway writer
     * @param now snapshot evaluation time
     */
    private void synchronizeOrganizationLocked(UUID organization, UUID leaseOwner,
            SpiceDbRelationshipWriter relationshipWriter, Instant now) {
        PreparedOrganizationSync prepared = snapshotTransactions.execute(status -> {
            OrganizationSyncState state = loadSyncStateForUpdate(organization, leaseOwner);
            if (state == null) return null;
            // Global policy changes may advance only the required revision, not the organization source version.
            // Capture that revision and every source fact in one view before releasing the SQL transaction.
            return new PreparedOrganizationSync(state, loadOrganizationAuthorizationSnapshot(organization, now));
        });
        if (prepared == null) return;
        OrganizationAuthorizationSnapshot organizationSnapshot = prepared.snapshot();
        synchronizeRelationships(organization, leaseOwner, relationshipWriter, now,
                organizationSnapshot.relationships().stream().sorted().toList(),
                organizationSnapshot.authorizationVersion(), organizationSnapshot.nextBoundary(), prepared.state());
    }

    /**
     * Applies an already constructed desired-state set under the current lease and revision fence.
     * @param organization projected organization
     * @param leaseOwner current worker lease
     * @param relationshipWriter bounded gateway writer
     * @param now attempt timestamp
     * @param desiredRelationships desired tuple set
     * @param snapshotSourceVersion source version used to construct the set
     * @param nextBoundary next scheduled authorization transition
     * @throws IllegalStateException when called inside a SQL transaction
     */
    void synchronizeRelationships(UUID organization, UUID leaseOwner, SpiceDbRelationshipWriter relationshipWriter,
            Instant now, List<SpiceDbRelationship> desiredRelationships, long snapshotSourceVersion,
            Instant nextBoundary) {
        requireOutsideTransaction();
        OrganizationSyncState before = loadSyncState(organization, leaseOwner);
        if (before == null) return;
        synchronizeRelationships(organization, leaseOwner, relationshipWriter, now, desiredRelationships,
                snapshotSourceVersion, nextBoundary, before);
    }

    /**
     * Applies a snapshot only against the exact fence captured with its source facts.
     * @param organization projected organization
     * @param leaseOwner current worker lease
     * @param relationshipWriter bounded gateway writer
     * @param now attempt timestamp
     * @param desiredRelationships coherent desired tuple set
     * @param snapshotSourceVersion source organization version
     * @param nextBoundary next scheduled authorization transition
     * @param before revision and source fence captured with the snapshot
     */
    private void synchronizeRelationships(UUID organization, UUID leaseOwner, SpiceDbRelationshipWriter relationshipWriter,
            Instant now, List<SpiceDbRelationship> desiredRelationships, long snapshotSourceVersion,
            Instant nextBoundary, OrganizationSyncState before) {
        requireOutsideTransaction();
        if (before.requiredSourceVersion() != snapshotSourceVersion) {
            scheduleRetry(organization, leaseOwner, now, "SOURCE_CHANGED_BEFORE_SYNC");
            return;
        }
        List<SpiceDbRelationship> previouslySyncedRelationships = loadPreviouslySyncedRelationships(organization);
        Set<SpiceDbRelationship> desiredRelationshipSet = new HashSet<>(desiredRelationships);
        List<SpiceDbRelationship> relationshipsToRemove = previouslySyncedRelationships.stream().filter(relationship -> !desiredRelationshipSet.contains(relationship)).toList();
        if (!recordPotentiallyWrittenRelationships(organization, leaseOwner, before, desiredRelationships, now)) {
            scheduleRetry(organization, leaseOwner, now, "SOURCE_CHANGED_BEFORE_SYNC");
            return;
        }
        BatchWriteResult touched = writeRelationshipBatches(organization, leaseOwner, before, relationshipWriter,
                desiredRelationships, com.authzed.api.v1.RelationshipUpdate.Operation.OPERATION_TOUCH, before.zedToken());
        if (!touched.complete()) {
            scheduleRetry(organization, leaseOwner, now, "SOURCE_CHANGED_DURING_SYNC");
            return;
        }
        BatchWriteResult removed = writeRelationshipBatches(organization, leaseOwner, before, relationshipWriter,
                relationshipsToRemove, com.authzed.api.v1.RelationshipUpdate.Operation.OPERATION_DELETE, touched.token());
        if (!removed.complete()) {
            scheduleRetry(organization, leaseOwner, now, "SOURCE_CHANGED_DURING_SYNC");
            return;
        }
        OrganizationSyncState after = loadSyncState(organization, leaseOwner);
        if (after == null) return;
        if (after.requiredRevision() != before.requiredRevision()
                || after.requiredSourceVersion() != before.requiredSourceVersion()
                || after.requiredSourceVersion() != snapshotSourceVersion) {
            scheduleRetry(organization, leaseOwner, now, "SOURCE_CHANGED_DURING_SYNC");
            return;
        }
        acknowledgeProjection(organization, leaseOwner, before.requiredRevision(), before.requiredSourceVersion(),
                snapshotSourceVersion, nextBoundary,
                desiredRelationships, removed.token(), now);
    }

    /**
     * Replaces the intent ledger only after every batch and the exact source fence are acknowledged.
     * @param organization projected organization
     * @param leaseOwner current worker lease
     * @param requiredRevision captured required revision
     * @param requiredSourceVersion captured source fence
     * @param snapshotSourceVersion source snapshot version
     * @param nextBoundary next scheduled authorization transition
     * @param desiredRelationships fully applied desired tuple set
     * @param appliedZedToken exact committed remote write token
     * @param now acknowledgement timestamp
     */
    void acknowledgeProjection(UUID organization, UUID leaseOwner, long requiredRevision, long requiredSourceVersion,
            long snapshotSourceVersion, Instant nextBoundary, List<SpiceDbRelationship> desiredRelationships,
            String appliedZedToken, Instant now) {
        if (appliedZedToken == null || appliedZedToken.isBlank()) {
            scheduleRetry(organization, leaseOwner, now, "MISSING_WRITE_TOKEN");
            return;
        }
        tx.execute(status -> {
            OrganizationSyncState current = loadSyncStateForUpdate(organization, leaseOwner);
            if (current == null || current.requiredRevision() != requiredRevision
                    || current.requiredSourceVersion() != requiredSourceVersion
                    || current.requiredSourceVersion() != snapshotSourceVersion) return null;
            jdbc.update("DELETE FROM spicedb_organization_sync_tuple WHERE organization_id=?", bytes(organization));
            for (SpiceDbRelationship relationship : desiredRelationships) {
                jdbc.update("""
                    INSERT INTO spicedb_organization_sync_tuple(organization_id,tuple_hash,resource_type,resource_id,relation_name,subject_type,subject_id,created_at)
                    VALUES(?,?,?,?,?,?,?,?)
                    """, bytes(organization), java.util.HexFormat.of().parseHex(relationship.hash()), relationship.resourceType(), relationship.resourceId(),
                        relationship.relation(), relationship.subjectType(), relationship.subjectId(), Timestamp.from(now));
            }
            jdbc.update("""
                UPDATE spicedb_organization_sync_state SET applied_revision=required_revision,applied_source_version=?,
                    sync_status='APPLIED',zed_token=?,next_boundary_at=?,lease_owner=NULL,lease_until=NULL,
                    attempts=0,available_at=?,last_error_code=NULL,updated_at=?
                WHERE organization_id=? AND lease_owner=? AND required_revision=? AND required_source_version=?
                """, snapshotSourceVersion, appliedZedToken, nextBoundary == null ? null : Timestamp.from(nextBoundary),
                    Timestamp.from(now), Timestamp.from(now), bytes(organization), bytes(leaseOwner), requiredRevision,
                    requiredSourceVersion);
            return null;
        });
    }

    /**
     * Stops a superseded or expired worker before it issues another remote batch.
     * @param organization projected organization
     * @param leaseOwner current worker lease
     * @param expected fence captured with the source snapshot
     * @param relationshipWriter gateway writer
     * @param relationships tuples in this pass
     * @param operation idempotent touch or exact delete
     * @param token previously acknowledged write token
     * @return completion state and the last exact committed token
     */
    private BatchWriteResult writeRelationshipBatches(UUID organization, UUID leaseOwner, OrganizationSyncState expected,
            SpiceDbRelationshipWriter relationshipWriter,
            List<SpiceDbRelationship> relationships,
            com.authzed.api.v1.RelationshipUpdate.Operation operation, String token) {
        for (int start = 0; start < relationships.size(); start += properties.maxBatchSize()) {
            OrganizationSyncState current = loadSyncState(organization, leaseOwner);
            if (current == null || current.requiredRevision() != expected.requiredRevision()
                    || current.requiredSourceVersion() != expected.requiredSourceVersion())
                return new BatchWriteResult(false, token);
            List<com.authzed.api.v1.RelationshipUpdate> batch = relationships.subList(start,
                    Math.min(start + properties.maxBatchSize(), relationships.size())).stream().map(relationship -> relationship.update(operation)).toList();
            token = relationshipWriter.writeRelationships(batch);
        }
        return new BatchWriteResult(true, token);
    }

    private boolean recordPotentiallyWrittenRelationships(UUID organization, UUID leaseOwner,
            OrganizationSyncState before, List<SpiceDbRelationship> desiredRelationships, Instant now) {
        return Boolean.TRUE.equals(tx.execute(status -> {
            OrganizationSyncState current = loadSyncStateForUpdate(organization, leaseOwner);
            if (current == null || current.requiredRevision() != before.requiredRevision()
                    || current.requiredSourceVersion() != before.requiredSourceVersion()) return false;
            // A failed or superseded remote pass may have touched any desired tuple. Keeping its
            // intent in the ledger lets the next pass delete tuples absent from its fresh snapshot.
            for (SpiceDbRelationship relationship : desiredRelationships) {
                jdbc.update("""
                    INSERT IGNORE INTO spicedb_organization_sync_tuple
                        (organization_id,tuple_hash,resource_type,resource_id,relation_name,subject_type,subject_id,created_at)
                    VALUES(?,?,?,?,?,?,?,?)
                    """, bytes(organization), java.util.HexFormat.of().parseHex(relationship.hash()),
                        relationship.resourceType(), relationship.resourceId(), relationship.relation(),
                        relationship.subjectType(), relationship.subjectId(), Timestamp.from(now));
            }
            return true;
        }));
    }

    private OrganizationSyncState loadSyncState(UUID organization, UUID leaseOwner) {
        List<OrganizationSyncState> rows = jdbc.query("SELECT required_revision,required_source_version,zed_token FROM spicedb_organization_sync_state WHERE organization_id=? AND lease_owner=? AND lease_until>UTC_TIMESTAMP(6)",
                (rs, row) -> new OrganizationSyncState(rs.getLong(1), rs.getLong(2), rs.getString(3)), bytes(organization), bytes(leaseOwner));
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private OrganizationSyncState loadSyncStateForUpdate(UUID organization, UUID leaseOwner) {
        List<OrganizationSyncState> rows = jdbc.query("SELECT required_revision,required_source_version,zed_token FROM spicedb_organization_sync_state WHERE organization_id=? AND lease_owner=? AND lease_until>UTC_TIMESTAMP(6) FOR UPDATE",
                (rs, row) -> new OrganizationSyncState(rs.getLong(1), rs.getLong(2), rs.getString(3)), bytes(organization), bytes(leaseOwner));
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private List<SpiceDbRelationship> loadPreviouslySyncedRelationships(UUID organization) {
        return jdbc.query("SELECT resource_type,resource_id,relation_name,subject_type,subject_id FROM spicedb_organization_sync_tuple WHERE organization_id=?",
                (rs, row) -> new SpiceDbRelationship(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5)), bytes(organization));
    }

    private void scheduleRetry(UUID organization, UUID leaseOwner, Instant now, String errorCode) {
        tx.execute(status -> {
            jdbc.update("""
                UPDATE spicedb_organization_sync_state SET attempts=attempts+1,sync_status='PENDING',
                    available_at=TIMESTAMPADD(SECOND,LEAST(300,POW(2,LEAST(attempts,8))),?),
                    lease_owner=NULL,lease_until=NULL,last_error_code=?,updated_at=?
                WHERE organization_id=? AND lease_owner=?
                """, Timestamp.from(now), errorCode, Timestamp.from(now), bytes(organization), bytes(leaseOwner));
            return null;
        });
    }

    /**
     * Builds tuple facts only from accounts and membership anchors belonging to the same organization.
     * @param organization projected tenant
     * @param now coherent snapshot evaluation time
     * @return desired relationships, source version and next scheduled transition
     * @throws IllegalStateException when active group ancestry is invalid
     */
    private OrganizationAuthorizationSnapshot loadOrganizationAuthorizationSnapshot(UUID organization, Instant now) {
        long authorizationVersion = jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?", Long.class, bytes(organization));
        Set<SpiceDbRelationship> relationships = new HashSet<>();
        String organizationStatus=jdbc.queryForObject("SELECT status FROM organization WHERE id=?",String.class,bytes(organization));
        if(!"ACTIVE".equals(organizationStatus)) return new OrganizationAuthorizationSnapshot(authorizationVersion,relationships,null);
        String organizationId = organization.toString();
        jdbc.query("""
            SELECT BIN_TO_UUID(m.account_id) FROM organization_membership m
            JOIN organization o ON o.id=m.organization_id AND o.status='ACTIVE'
            JOIN user_account a ON a.id=m.account_id AND a.organization_id=m.organization_id AND a.type=o.type AND a.status='ACTIVE'
            JOIN users u ON u.id=a.user_id AND u.status='ACTIVE' WHERE m.organization_id=? AND m.status='ACTIVE'
              AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=m.organization_id
                AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED','PURGED'))
            """, rs -> { add(relationships, "organization", organizationId, "account_member", "account", rs.getString(1)); }, bytes(organization));

        Map<UUID, Group> groups = new HashMap<>();
        jdbc.query("SELECT BIN_TO_UUID(id),BIN_TO_UUID(parent_group_id),type,status FROM iam_group WHERE organization_id=? AND workspace_context='ORGANIZATION'",
                rs -> { UUID id=UUID.fromString(rs.getString(1)); groups.put(id,new Group(id,rs.getString(2)==null?null:UUID.fromString(rs.getString(2)),rs.getString(3),rs.getString(4))); }, bytes(organization));
        for (Group group : groups.values()) {
            if (!"ACTIVE".equals(group.status())) continue;
            String type = "DEPARTMENT".equals(group.type()) ? "department" : "team";
            relationships.add(relationship(type, group.id().toString(), "organization", "organization", organizationId));
            if (group.parent() != null) {
                Group parent = groups.get(group.parent());
                if (parent == null || !"ACTIVE".equals(parent.status())) throw new IllegalStateException("Invalid organization group ancestry.");
                int depth = 0; Group cursor = group;
                Set<UUID> visited = new HashSet<>();
                while (cursor != null) { if (!visited.add(cursor.id()) || ++depth > MAX_GROUP_DEPTH) throw new IllegalStateException("Organization group ancestry exceeds its safe depth."); cursor=cursor.parent()==null?null:groups.get(cursor.parent()); }
                String parentType = "DEPARTMENT".equals(parent.type()) ? "department" : "team";
                relationships.add(relationship(type, group.id().toString(), "parent", parentType, parent.id().toString()));
            }
        }
        jdbc.query("""
            SELECT BIN_TO_UUID(gm.group_id),BIN_TO_UUID(gm.account_id) FROM group_membership gm
            JOIN organization_membership om ON om.id=gm.organization_membership_id
              AND om.organization_id=gm.organization_id AND om.account_id=gm.account_id AND om.status='ACTIVE'
            JOIN organization o ON o.id=gm.organization_id AND o.status='ACTIVE'
            JOIN user_account a ON a.id=gm.account_id AND a.organization_id=gm.organization_id AND a.type=o.type AND a.status='ACTIVE'
            JOIN users u ON u.id=a.user_id AND u.status='ACTIVE'
            JOIN iam_group g ON g.id=gm.group_id AND g.organization_id=gm.organization_id
              AND g.workspace_context='ORGANIZATION' AND g.status='ACTIVE'
            WHERE gm.organization_id=? AND gm.status='ACTIVE' AND gm.valid_from<=? AND (gm.valid_until IS NULL OR gm.valid_until>?)
              AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=gm.organization_id
                AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED','PURGED'))
            """, rs -> { String group=rs.getString(1); Group g=groups.get(UUID.fromString(group)); if(g!=null) add(relationships, objectType(g),group,"account_member","account",rs.getString(2)); },
                bytes(organization),Timestamp.from(now),Timestamp.from(now));

        // Baseline and category ceiling are distinct source bindings and distinct SpiceDB relations.
        addRoleGrants(organization, "iam_context_member_role_binding", "capability", "scoped_grantee", groups, relationships);
        addRoleGrants(organization, "iam_stakeholder_role_binding", "category_capability", "category_grantee", groups, relationships);
        addProfessionalGrants(organization, now, groups, relationships);
        addRestrictions(organization, now, groups, relationships);
        Instant nextBoundary = nextBoundary(organization, now);
        return new OrganizationAuthorizationSnapshot(authorizationVersion, relationships, nextBoundary);
    }

    /**
     * Projects active category or baseline authorities for tenant-bound eligible members.
     * @param organization projected tenant
     * @param bindingTable server-selected category or baseline binding table
     * @param relation owning scope's capability relation
     * @param grantRelation separate category or scoped grant relation
     * @param groups organization-owned groups in the source snapshot
     * @param relationships desired tuple set to extend
     */
    private void addRoleGrants(UUID organization, String bindingTable, String relation, String grantRelation, Map<UUID,Group> groups,
            Set<SpiceDbRelationship> relationships) {
        String sql = """
                SELECT BIN_TO_UUID(ra.authority_id),BIN_TO_UUID(m.account_id) FROM %s b
                JOIN iam_role r ON r.id=b.role_id AND r.status='ACTIVE'
                JOIN iam_role_authority ra ON ra.role_id=r.id
                JOIN iam_authority authority ON authority.id=ra.authority_id AND authority.status='ACTIVE'
                JOIN organization_membership m ON m.organization_id=? AND m.status='ACTIVE'
                JOIN organization o ON o.id=m.organization_id AND o.status='ACTIVE'
                JOIN user_account a ON a.id=m.account_id AND a.organization_id=m.organization_id
                  AND a.type=o.type AND a.status='ACTIVE'
                JOIN users u ON u.id=a.user_id AND u.status='ACTIVE'
                WHERE b.status='ACTIVE' AND b.category_key='ORGANIZATION'
                  AND NOT EXISTS(SELECT 1 FROM organization_account_restriction x WHERE x.organization_id=m.organization_id
                    AND x.user_id=u.id AND x.status IN('REMOVED','BLACKLISTED','PURGED'))
                """.formatted(bindingTable);
        jdbc.query(sql, rs -> {
            String authority=rs.getString(1), account=rs.getString(2), cap=capabilityId(organization.toString(),authority);
            relationships.add(relationship("scope_capability",cap,"grantee","account",account));
            relationships.add(relationship("scope_capability",cap,grantRelation,"account",account));
            relationships.add(relationship("organization",organization.toString(),relation,"scope_capability",cap));
            for(Group group:groups.values()) {
                if(!"ACTIVE".equals(group.status())) continue;
                String parent=group.parent()==null?organization.toString():group.parent().toString();
                relationships.add(relationship("scope_capability",capabilityId(group.id().toString(),authority),"parent","scope_capability",
                        capabilityId(parent,authority)));
                relationships.add(relationship(objectType(group),group.id().toString(),relation,"scope_capability",capabilityId(group.id().toString(),authority)));
            }
        }, bytes(organization));
    }

    private void addRestrictions(UUID organization, Instant now, Map<UUID,Group> groups, Set<SpiceDbRelationship> relationships) {
        jdbc.query("""
            SELECT BIN_TO_UUID(COALESCE(r.group_id,r.organization_id)),BIN_TO_UUID(r.operation_id),BIN_TO_UUID(r.account_id)
            FROM iam_professional_restriction r WHERE r.organization_id=? AND r.status='ACTIVE' AND r.valid_from<=?
              AND (r.valid_until IS NULL OR r.valid_until>?)
            """, rs -> {
                String scope=rs.getString(1), operation=rs.getString(2), account=rs.getString(3);
                UUID scopeId=UUID.fromString(scope); Group group=groups.get(scopeId);
                if (!scopeId.equals(organization) && group==null) return;
                String type=scopeId.equals(organization)?"organization":objectType(group);
                if (account==null) relationships.add(relationship(type,scope,"denied_operation","operation",operation));
                else {
                    String opId=operationId(scope,operation);
                    relationships.add(relationship("scope_operation",opId,"denied_account","account",account));
                    relationships.add(relationship(type,scope,"operation_restriction","scope_operation",opId));
                    addOperationParents(relationships,opId,scopeId,operation,organization,groups);
                }
            },bytes(organization),Timestamp.from(now),Timestamp.from(now));
        jdbc.query("""
            SELECT BIN_TO_UUID(r.operation_id),BIN_TO_UUID(r.account_id) FROM iam_operation_restriction r
            WHERE r.category_key='ORGANIZATION' AND r.status='ACTIVE' AND r.valid_from<=?
              AND (r.valid_until IS NULL OR r.valid_until>?)
              AND (r.account_id IS NULL OR EXISTS(SELECT 1 FROM organization_membership m WHERE m.organization_id=? AND m.account_id=r.account_id AND m.status='ACTIVE'))
            """, rs -> {
                String operation=rs.getString(1),account=rs.getString(2);
                if(account==null) relationships.add(relationship("organization",organization.toString(),"denied_operation","operation",operation));
                else {
                    String opId=operationId(organization.toString(),operation);
                    relationships.add(relationship("scope_operation",opId,"denied_account","account",account));
                    relationships.add(relationship("organization",organization.toString(),"operation_restriction","scope_operation",opId));
                }
            },Timestamp.from(now),Timestamp.from(now),bytes(organization));
    }

    private static void addOperationParents(Set<SpiceDbRelationship> relationships,String opId,UUID scope,String operation,
            UUID organization,Map<UUID,Group> groups) {
        UUID parent=scope.equals(organization)?null:groups.get(scope).parent();
        if(parent==null && !scope.equals(organization)) parent=organization;
        String childId=opId;
        Set<UUID> visited=new HashSet<>();
        int depth=0;
        while(parent!=null) {
            if(!visited.add(parent) || ++depth>MAX_GROUP_DEPTH+1) throw new IllegalStateException("Operation restriction ancestry is invalid.");
            String parentId=operationId(parent.toString(),operation);
            relationships.add(relationship("scope_operation",childId,"parent","scope_operation",parentId));
            childId=parentId;
            parent=parent.equals(organization)?null:groups.get(parent).parent();
            if(parent==null && !childId.startsWith(compactUuid(organization.toString()))) parent=organization;
        }
    }

    /**
     * Projects eligible responsibility grants at their declared logical scope and current membership anchor.
     * @param organization projected tenant
     * @param now coherent snapshot evaluation time
     * @param groups organization-owned groups in the source snapshot
     * @param relationships desired tuple set to extend
     */
    private void addProfessionalGrants(UUID organization, Instant now, Map<UUID,Group> groups, Set<SpiceDbRelationship> relationships) {
        Map<String,Set<String>> authoritiesByScope = new HashMap<>();
        jdbc.query("""
            SELECT BIN_TO_UUID(COALESCE(a.group_id,a.organization_id)),BIN_TO_UUID(ra.authority_id),BIN_TO_UUID(a.account_id)
            FROM iam_professional_assignment a JOIN organization_membership m ON m.id=a.membership_id
              AND m.organization_id=a.organization_id AND m.account_id=a.account_id AND m.status='ACTIVE'
            JOIN organization o ON o.id=a.organization_id AND o.status='ACTIVE'
            JOIN user_account ua ON ua.id=a.account_id AND ua.organization_id=a.organization_id AND ua.type=o.type AND ua.status='ACTIVE'
            JOIN users u ON u.id=ua.user_id AND u.status='ACTIVE'
            JOIN iam_professional_responsibility p ON p.role_id=a.role_id JOIN iam_role r ON r.id=a.role_id AND r.status='ACTIVE'
            JOIN iam_role_authority ra ON ra.role_id=r.id
            JOIN iam_authority authority ON authority.id=ra.authority_id AND authority.status='ACTIVE'
            WHERE a.organization_id=? AND a.status='ACTIVE' AND a.valid_from<=? AND (a.valid_until IS NULL OR a.valid_until>?)
              AND ((a.group_id IS NULL AND p.scope_kind='ORGANIZATION') OR EXISTS(SELECT 1 FROM iam_group g
                WHERE g.organization_id=a.organization_id AND g.id=a.group_id AND g.status='ACTIVE'
                  AND g.workspace_context='ORGANIZATION'
                  AND p.scope_kind=CASE WHEN g.type='DEPARTMENT' THEN 'DEPARTMENT'
                    WHEN g.type IN('TEAM','PROJECT','CUSTOM') THEN 'TEAM' END))
              AND (a.group_id IS NULL OR EXISTS(SELECT 1 FROM group_membership gm WHERE gm.organization_id=a.organization_id
                AND gm.group_id=a.group_id AND gm.account_id=a.account_id
                AND gm.organization_membership_id=a.membership_id AND gm.status='ACTIVE'
                AND gm.valid_from<=? AND (gm.valid_until IS NULL OR gm.valid_until>?)))
              AND NOT EXISTS(SELECT 1 FROM organization_account_restriction x WHERE x.organization_id=a.organization_id
                AND x.user_id=u.id AND x.status IN('REMOVED','BLACKLISTED','PURGED'))
            """, rs -> {
                String scope=rs.getString(1), authority=rs.getString(2), account=rs.getString(3);
                UUID scopeId=UUID.fromString(scope); if(!scopeId.equals(organization) && !groups.containsKey(scopeId)) return;
                String cap=capabilityId(scope,authority);
                relationships.add(relationship("scope_capability",cap,"grantee","account",account));
                relationships.add(relationship("scope_capability",cap,"scoped_grantee","account",account));
                relationships.add(relationship("scope_capability",cap,"responsibility_grantee","account",account));
                String type=scopeId.equals(organization)?"organization":objectType(groups.get(scopeId));
                relationships.add(relationship(type,scope,"capability","scope_capability",cap));
                authoritiesByScope.computeIfAbsent(authority,key->new HashSet<>()).add(scope);
            }, bytes(organization),Timestamp.from(now),Timestamp.from(now),Timestamp.from(now),Timestamp.from(now));
        for (String authority : authoritiesByScope.keySet()) {
            for (Group child : groups.values()) {
                if (!"ACTIVE".equals(child.status()) || child.parent()==null) continue;
                relationships.add(relationship("scope_capability",capabilityId(child.id().toString(),authority),"parent","scope_capability",
                        capabilityId(child.parent().toString(),authority)));
            }
            for (Group group : groups.values()) {
                if ("ACTIVE".equals(group.status()) && group.parent()==null) relationships.add(relationship("scope_capability",capabilityId(group.id().toString(),authority),"parent","scope_capability",
                        capabilityId(organization.toString(),authority)));
            }
        }
    }

    private Instant nextBoundary(UUID organization, Instant now) {
        List<Timestamp> boundaries=jdbc.query("""
            SELECT valid_from FROM group_membership WHERE organization_id=? AND status='ACTIVE' AND valid_from>?
            UNION ALL SELECT valid_until FROM group_membership WHERE organization_id=? AND status='ACTIVE' AND valid_until>?
            UNION ALL SELECT valid_from FROM iam_professional_assignment WHERE organization_id=? AND status='ACTIVE' AND valid_from>?
            UNION ALL SELECT valid_until FROM iam_professional_assignment WHERE organization_id=? AND status='ACTIVE' AND valid_until>?
            UNION ALL SELECT valid_from FROM iam_professional_restriction WHERE organization_id=? AND status='ACTIVE' AND valid_from>?
            UNION ALL SELECT valid_until FROM iam_professional_restriction WHERE organization_id=? AND status='ACTIVE' AND valid_until>?
            UNION ALL SELECT valid_from FROM iam_operation_restriction WHERE category_key='ORGANIZATION' AND status='ACTIVE' AND valid_from>?
            UNION ALL SELECT valid_until FROM iam_operation_restriction WHERE category_key='ORGANIZATION' AND status='ACTIVE' AND valid_until>?
            """,(rs,row)->rs.getTimestamp(1),bytes(organization),Timestamp.from(now),bytes(organization),Timestamp.from(now),bytes(organization),Timestamp.from(now),bytes(organization),Timestamp.from(now),bytes(organization),Timestamp.from(now),bytes(organization),Timestamp.from(now),Timestamp.from(now),Timestamp.from(now));
        return boundaries.stream().filter(java.util.Objects::nonNull).map(Timestamp::toInstant).min(Instant::compareTo).orElse(null);
    }

    private static String objectType(Group group) { return "DEPARTMENT".equals(group.type())?"department":"team"; }
    private static String capabilityId(String scope, String authority) { return compactUuid(scope) + compactUuid(authority); }
    private static String operationId(String scope,String operation) { return compactUuid(scope) + compactUuid(operation); }
    private static String compactUuid(String value) { return value.replace("-", ""); }
    private static SpiceDbRelationship relationship(String rt,String ri,String rel,String st,String si) { return new SpiceDbRelationship(rt,ri,rel,st,si); }
    private static void add(Set<SpiceDbRelationship> relationships,String rt,String ri,String rel,String st,String si) { relationships.add(relationship(rt,ri,rel,st,si)); }
    private static byte[] bytes(UUID id) { return java.nio.ByteBuffer.allocate(16).putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits()).array(); }
    private static UUID uuid(byte[] bytes) { java.nio.ByteBuffer b=java.nio.ByteBuffer.wrap(bytes); return new UUID(b.getLong(),b.getLong()); }
    /**
     * Prevents callers from holding SQL transactions across relationship RPCs.
     * @throws IllegalStateException when synchronization is invoked inside a transaction
     */
    private static void requireOutsideTransaction() {
        if (TransactionSynchronizationManager.isActualTransactionActive())
            throw new IllegalStateException("SpiceDB synchronization requires no active SQL transaction.");
    }
    private record Group(UUID id, UUID parent, String type, String status) {}
    private record OrganizationSyncState(long requiredRevision, long requiredSourceVersion, String zedToken) {}
    private record OrganizationAuthorizationSnapshot(long authorizationVersion,Set<SpiceDbRelationship> relationships,Instant nextBoundary) {}
    private record PreparedOrganizationSync(OrganizationSyncState state, OrganizationAuthorizationSnapshot snapshot) {}
    private record BatchWriteResult(boolean complete, String token) {}
}
