package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.RelationshipUpdate;
import io.grpc.Status;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Failure/replay evidence for immutable committed intent; no SQL schema or application is started. */
class IndividualSpiceDbProjectionWorkerTests {
    private final IntentJdbc jdbc=new IntentJdbc();
    private final SpiceDbRelationshipWriter writer=mock(SpiceDbRelationshipWriter.class);

    /** A partial batch never acknowledges; restart repeats exact idempotent tuples. */
    @Test void partialWriteAndLostAcknowledgementRetryWithoutEarlyAcknowledgement() {
        when(writer.maxBatchSize()).thenReturn(2);
        when(writer.writeRelationships(any())).thenReturn("first").thenThrow(Status.UNAVAILABLE.asRuntimeException());
        worker().publish();assertFalse(jdbc.applied);assertEquals(1,jdbc.retries);
        reset(writer);when(writer.maxBatchSize()).thenReturn(2);
        when(writer.writeRelationships(any())).thenAnswer(call->{
            assertFalse(TransactionSynchronizationManager.isActualTransactionActive());
            List<RelationshipUpdate> updates=call.getArgument(0);assertTrue(updates.size()<=2);
            assertTrue(updates.stream().allMatch(update->update.getOperation()==RelationshipUpdate.Operation.OPERATION_TOUCH));
            return "committed";
        });
        worker().publish();assertTrue(jdbc.applied);assertEquals("committed",jdbc.token);
        clearInvocations(writer);worker().publish();verifyNoInteractions(writer);
    }

    /** A failed SQL acknowledgement leaves intent pending even after graph success. */
    @Test void lostSqlAcknowledgementDoesNotLoseCommittedTupleIntent() {
        when(writer.maxBatchSize()).thenReturn(100);when(writer.writeRelationships(any())).thenReturn("committed");
        jdbc.loseAck=true;worker().publish();assertFalse(jdbc.applied);
        jdbc.loseAck=false;worker().publish();assertTrue(jdbc.applied);verify(writer,times(2)).writeRelationships(any());
    }

    /** Oversized/corrupt snapshots are rejected before remote writes or acknowledgement. */
    @Test void oversizedIntentCannotPublish() {
        jdbc.count=65;when(writer.maxBatchSize()).thenReturn(100);
        worker().publish();assertFalse(jdbc.applied);assertEquals(1,jdbc.retries);verify(writer,never()).writeRelationships(any());
    }

    /** A group candidate is written only for an admitted exact personal group and never a fabricated organization. */
    @Test void groupProjectionUsesOnlyIamOwnedPersonalTypes() {
        jdbc.group=UUID.randomUUID();when(writer.maxBatchSize()).thenReturn(100);
        when(writer.writeRelationships(any())).thenAnswer(call->{
            List<RelationshipUpdate> updates=call.getArgument(0);
            assertEquals(1,updates.stream().filter(update->update.getRelationship().getResource().getObjectType().equals("individual_group")).count());
            assertTrue(updates.stream().noneMatch(update->update.getRelationship().getResource().getObjectType().equals("organization")));
            return "committed";
        });worker().publish();assertTrue(jdbc.applied);
    }

    /** @return independent worker using the same durable simulated intent */
    private IndividualSpiceDbProjectionWorker worker() { return new IndividualSpiceDbProjectionWorker(jdbc,writer,Clock.systemUTC(),new SimpleMeterRegistry()); }
    private static final class IntentJdbc extends JdbcTemplate {
        private final UUID account=UUID.randomUUID();
        private UUID group;
        private int count=2,retries;
        private boolean applied,loseAck;
        private String token;
        @Override public <T> List<T> query(String sql,RowMapper<T> mapper) { return query(sql,mapper,new Object[0]); }
        @Override public <T> List<T> query(String sql,RowMapper<T> mapper,Object... args) {
            try {
                if(sql.contains("FROM iam_individual_graph_intent")) {
                    if(applied)return List.of();
                    ResultSet row=mock(ResultSet.class);when(row.getString(1)).thenReturn("a".repeat(64));
                    when(row.getBytes(2)).thenReturn(bytes(account));when(row.getBytes(3)).thenReturn(group==null?null:bytes(group));
                    return List.of(mapper.mapRow(row,0));
                }
                List<T> result=new ArrayList<>();
                for(int index=0;index<count;index++) {
                    ResultSet row=mock(ResultSet.class);when(row.getBytes(1)).thenReturn(bytes(new UUID(0,index+1)));
                    when(row.getBoolean(2)).thenReturn(true);when(row.getBoolean(3)).thenReturn(true);
                    result.add(mapper.mapRow(row,index));
                }return result;
            }catch(SQLException failure){throw new AssertionError(failure);}
        }
        @Override public int update(String sql,Object... args) {
            if(sql.contains("SET applied_at")) {
                if(loseAck)throw new org.springframework.dao.TransientDataAccessResourceException("Lost ack");
                applied=true;token=(String)args[1];
            }else retries++;
            return 1;
        }
    }
}
