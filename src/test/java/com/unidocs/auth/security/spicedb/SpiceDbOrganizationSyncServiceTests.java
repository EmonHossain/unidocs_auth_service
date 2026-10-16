package com.unidocs.auth.security.spicedb;

import java.sql.ResultSet;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import com.authzed.api.v1.RelationshipUpdate;
import io.grpc.Status;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verifyNoInteractions;

class SpiceDbOrganizationSyncServiceTests {
    /**
     * Rejects a snapshot when a global policy revision changes after preparation without a source-version change.
     * @throws Exception when the simulated advisory connection fails
     */
    @Test
    void globalRevisionChangedAfterSnapshotCannotUseANewerFence() throws Exception {
        InMemoryJdbc database = new InMemoryJdbc() {
            /** {@inheritDoc} */
            @Override public <T> T queryForObject(String sql, Class<T> type, Object... args) {
                if (sql.startsWith("SELECT authorization_version")) return type.cast(11L);
                if (sql.startsWith("SELECT status FROM organization")) return type.cast("INACTIVE");
                throw new AssertionError("Unexpected source snapshot query");
            }

            /** {@inheritDoc} */
            @Override public <T> T execute(org.springframework.jdbc.core.ConnectionCallback<T> callback) {
                try {
                    java.sql.Connection connection = mock(java.sql.Connection.class);
                    java.sql.PreparedStatement statement = mock(java.sql.PreparedStatement.class);
                    ResultSet row = mock(ResultSet.class);
                    when(connection.prepareStatement(anyString())).thenReturn(statement);
                    when(statement.executeQuery()).thenReturn(row);
                    when(row.next()).thenReturn(true);
                    when(row.getInt(1)).thenReturn(1);
                    return callback.doInConnection(connection);
                } catch (java.sql.SQLException failure) {
                    throw new AssertionError(failure);
                }
            }
        };
        SpiceDbRelationship existing = new SpiceDbRelationship("team", "retained", "account_member", "account", "actor");
        database.ledger.add(existing);
        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        java.util.concurrent.atomic.AtomicInteger commits = new java.util.concurrent.atomic.AtomicInteger();
        org.mockito.Mockito.doAnswer(call -> {
            if (commits.incrementAndGet() == 1) database.revision++;
            return null;
        }).when(manager).commit(any());
        SpiceDbRelationshipWriter writer = mock(SpiceDbRelationshipWriter.class);
        SpiceDbOrganizationSyncService sync = new SpiceDbOrganizationSyncService(database, manager,
                mock(SpiceDbOrganizationSyncProperties.class));

        sync.synchronizeOrganization(organization, leaseOwner, writer, now);

        verifyNoInteractions(writer);
        assertEquals(0, database.acknowledgements);
        assertEquals(List.of(existing), database.ledger);
        verify(manager).getTransaction(org.mockito.ArgumentMatchers.argThat(definition ->
                definition.getIsolationLevel() == org.springframework.transaction.TransactionDefinition.ISOLATION_REPEATABLE_READ
                && definition.getPropagationBehavior() == org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW));
    }

    @Test
    void sourceChangedWhileBuildingSnapshotDoesNotWriteStaleTuples() {
        InMemoryJdbc database=new InMemoryJdbc();
        database.sourceVersion=12;
        PlatformTransactionManager manager=mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        SpiceDbOrganizationSyncService sync=new SpiceDbOrganizationSyncService(database,manager,
                mock(SpiceDbOrganizationSyncProperties.class));
        SpiceDbRelationshipWriter writer=mock(SpiceDbRelationshipWriter.class);

        sync.synchronizeRelationships(organization,leaseOwner,writer,now,List.of(
                new SpiceDbRelationship("team","stale","account_member","account","actor")),11,null);

        verifyNoInteractions(writer);
        assertTrue(database.ledger.isEmpty());
        assertEquals(0,database.acknowledgements);
    }

    @Test
    void failedSecondBatchLeavesLedgerForRetryCleanup() {
        InMemoryJdbc database=new InMemoryJdbc();
        PlatformTransactionManager manager=mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        SpiceDbOrganizationSyncProperties properties=mock(SpiceDbOrganizationSyncProperties.class);
        when(properties.maxBatchSize()).thenReturn(1);
        SpiceDbOrganizationSyncService sync=new SpiceDbOrganizationSyncService(database,manager,properties);
        SpiceDbRelationshipWriter writer=mock(SpiceDbRelationshipWriter.class);
        SpiceDbRelationship stale=new SpiceDbRelationship("team","stale","account_member","account","actor");
        SpiceDbRelationship retained=new SpiceDbRelationship("team","retained","account_member","account","actor");
        List<RelationshipUpdate.Operation> operations=new ArrayList<>();
        when(writer.writeRelationships(any())).thenAnswer(invocation -> {
            RelationshipUpdate update=((List<RelationshipUpdate>)invocation.getArgument(0)).getFirst();
            operations.add(update.getOperation());
            assertEquals(2,database.ledger.size());
            if(operations.size()==2)throw Status.UNAVAILABLE.asRuntimeException();
            return "first-token";
        });

        assertThrows(io.grpc.StatusRuntimeException.class,()->sync.synchronizeRelationships(organization,leaseOwner,
                writer,now,List.of(stale,retained),11,null));
        assertEquals(2,database.ledger.size());
        assertEquals(0,database.acknowledgements);

        reset(writer);
        operations.clear();
        when(writer.writeRelationships(any())).thenAnswer(invocation -> {
            RelationshipUpdate update=((List<RelationshipUpdate>)invocation.getArgument(0)).getFirst();
            operations.add(update.getOperation());
            return "retry-token";
        });
        sync.synchronizeRelationships(organization,leaseOwner,writer,now,List.of(retained),11,null);

        assertEquals(List.of(RelationshipUpdate.Operation.OPERATION_TOUCH,
                RelationshipUpdate.Operation.OPERATION_DELETE),operations);
        assertEquals(List.of(retained),database.ledger);
        assertEquals(1,database.acknowledgements);
    }

    @Test
    void sourceSupersededDuringRemoteWritesKeepsLedgerForFreshReplay() {
        InMemoryJdbc database=new InMemoryJdbc();
        PlatformTransactionManager manager=mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        SpiceDbOrganizationSyncProperties properties=mock(SpiceDbOrganizationSyncProperties.class);
        when(properties.maxBatchSize()).thenReturn(1);
        SpiceDbOrganizationSyncService sync=new SpiceDbOrganizationSyncService(database,manager,properties);
        SpiceDbRelationshipWriter writer=mock(SpiceDbRelationshipWriter.class);
        SpiceDbRelationship stale=new SpiceDbRelationship("team","old","account_member","account","actor");
        SpiceDbRelationship current=new SpiceDbRelationship("team","new","account_member","account","actor");
        java.util.concurrent.atomic.AtomicInteger batches=new java.util.concurrent.atomic.AtomicInteger();
        when(writer.writeRelationships(any())).thenAnswer(invocation -> {
            if(batches.incrementAndGet()==1) {
                database.revision=9;
                database.sourceVersion=12;
            }
            return "superseded-token";
        });

        sync.synchronizeRelationships(organization,leaseOwner,writer,now,List.of(stale,current),11,null);
        assertEquals(1,batches.get());
        assertEquals(2,database.ledger.size());
        assertEquals(0,database.acknowledgements);

        reset(writer);
        List<RelationshipUpdate.Operation> replay=new ArrayList<>();
        when(writer.writeRelationships(any())).thenAnswer(invocation -> {
            replay.add(((List<RelationshipUpdate>)invocation.getArgument(0)).getFirst().getOperation());
            return "fresh-token";
        });
        sync.synchronizeRelationships(organization,leaseOwner,writer,now,List.of(current),12,null);

        assertEquals(List.of(RelationshipUpdate.Operation.OPERATION_TOUCH,
                RelationshipUpdate.Operation.OPERATION_DELETE),replay);
        assertEquals(List.of(current),database.ledger);
        assertEquals(1,database.acknowledgements);

        replay.clear();
        sync.synchronizeRelationships(organization,leaseOwner,writer,now,List.of(current),12,null);
        assertEquals(List.of(RelationshipUpdate.Operation.OPERATION_TOUCH),replay);
        assertEquals(List.of(current),database.ledger);
    }

    private static class InMemoryJdbc extends JdbcTemplate {
        private final List<SpiceDbRelationship> ledger=new ArrayList<>();
        private int acknowledgements;
        private long revision=8;
        private long sourceVersion=11;

        @Override public <T> List<T> query(String sql, RowMapper<T> mapper, Object... args) {
            try {
                if(sql.contains("FROM spicedb_organization_sync_state")) {
                    ResultSet row=mock(ResultSet.class);
                    when(row.getLong(1)).thenReturn(revision);
                    when(row.getLong(2)).thenReturn(sourceVersion);
                    when(row.getString(3)).thenReturn("old-token");
                    return List.of(mapper.mapRow(row,0));
                }
                if(sql.contains("FROM spicedb_organization_sync_tuple")) {
                    List<T> rows=new ArrayList<>();
                    for(SpiceDbRelationship relationship:ledger) {
                        ResultSet row=mock(ResultSet.class);
                        when(row.getString(1)).thenReturn(relationship.resourceType());
                        when(row.getString(2)).thenReturn(relationship.resourceId());
                        when(row.getString(3)).thenReturn(relationship.relation());
                        when(row.getString(4)).thenReturn(relationship.subjectType());
                        when(row.getString(5)).thenReturn(relationship.subjectId());
                        rows.add(mapper.mapRow(row,rows.size()));
                    }
                    return rows;
                }
                throw new AssertionError("Unexpected projection query");
            } catch(java.sql.SQLException failure) {
                throw new AssertionError(failure);
            }
        }

        @Override public int update(String sql, Object... args) {
            if(sql.contains("INTO spicedb_organization_sync_tuple")) {
                SpiceDbRelationship relationship=new SpiceDbRelationship((String)args[2],(String)args[3],
                        (String)args[4],(String)args[5],(String)args[6]);
                if(!ledger.contains(relationship))ledger.add(relationship);
            } else if(sql.contains("DELETE FROM spicedb_organization_sync_tuple")) {
                ledger.clear();
            } else if(sql.contains("UPDATE spicedb_organization_sync_state SET applied_revision")) {
                acknowledgements++;
            }
            return 1;
        }
    }

    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
    private final SpiceDbOrganizationSyncService service = new SpiceDbOrganizationSyncService(jdbc, transactions,
            mock(SpiceDbOrganizationSyncProperties.class));
    private final UUID organization = UUID.randomUUID();
    private final UUID leaseOwner = UUID.randomUUID();
    private final Instant now = Instant.parse("2026-10-31T10:00:00Z");

    @Test
    void newerRequiredSourceVersionCannotAcknowledgeOrReplaceTupleLedger() throws Exception {
        when(transactions.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        syncState(8, 12);

        service.acknowledgeProjection(organization, leaseOwner, 8, 11, 11, null, List.of(), "token", now);

        verify(jdbc, never()).update(contains("DELETE FROM spicedb_organization_sync_tuple"), any(byte[].class));
        verify(jdbc, never()).update(contains("UPDATE spicedb_organization_sync_state SET applied_revision"), any(Object[].class));
    }

    @Test
    void sourceVersionMissingFromSnapshotCannotAcknowledge() throws Exception {
        when(transactions.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        syncState(8, 11);

        service.acknowledgeProjection(organization, leaseOwner, 8, 11, 10, null, List.of(), "token", now);

        verify(jdbc, never()).update(contains("DELETE FROM spicedb_organization_sync_tuple"), any(byte[].class));
    }

    @Test
    void unchangedSourceVersionAcknowledgesUnderRowLock() throws Exception {
        when(transactions.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        syncState(8, 11);

        service.acknowledgeProjection(organization, leaseOwner, 8, 11, 11, null, List.of(), "token", now);

        verify(jdbc).update(contains("DELETE FROM spicedb_organization_sync_tuple"), any(byte[].class));
        verify(jdbc).update(contains("AND required_source_version=?"), any(Object[].class));
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void syncState(long revision, long sourceVersion) throws Exception {
        when(jdbc.query(anyString(), any(RowMapper.class), any(Object[].class))).thenAnswer(invocation -> {
            String sql = invocation.getArgument(0);
            assertTrue(sql.contains("FOR UPDATE"));
            ResultSet row = mock(ResultSet.class);
            when(row.getLong(1)).thenReturn(revision);
            when(row.getLong(2)).thenReturn(sourceVersion);
            return List.of(((RowMapper) invocation.getArgument(1)).mapRow(row, 0));
        });
    }
}
