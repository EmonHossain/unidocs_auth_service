package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.RelationshipUpdate;
import io.micrometer.core.instrument.MeterRegistry;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Publishes committed immutable personal capability intent using the IAM writer identity. */
@Component
@EnableScheduling
@ConditionalOnProperty(prefix = "auth.spicedb.individual", name = "publisher-enabled", havingValue = "true")
public final class IndividualSpiceDbProjectionWorker {
    private final JdbcTemplate jdbc;
    private final SpiceDbRelationshipWriter writer;
    private final Clock clock;
    private final MeterRegistry metrics;

    /**
     * Reuses the separately configured IAM projection channel; request credentials cannot write.
     * @param jdbc committed IAM intent storage
     * @param writer separately credentialed bounded writer
     * @param clock acknowledgement clock
     * @param metrics bounded worker metrics
     */
    public IndividualSpiceDbProjectionWorker(JdbcTemplate jdbc, SpiceDbRelationshipWriter writer, Clock clock, MeterRegistry metrics) {
        this.jdbc = jdbc; this.writer = writer; this.clock = clock; this.metrics = metrics;
    }

    /** Retries a bounded oldest-first page; duplicate workers and lost acknowledgements are idempotent. */
    @Scheduled(fixedDelayString = "${auth.spicedb.individual.publisher-delay-ms:1000}")
    public void publish() {
        if (TransactionSynchronizationManager.isActualTransactionActive()) throw new IllegalStateException("Publishing outside SQL only.");
        try {
            List<Intent> pending = jdbc.query("""
                    SELECT snapshot_id,account_id,group_id FROM iam_individual_graph_intent
                    WHERE applied_at IS NULL AND next_attempt_at<=UTC_TIMESTAMP(6)
                    ORDER BY next_attempt_at,created_at,snapshot_id LIMIT 20
                    """, (row, index) -> new Intent(row.getString(1), uuid(row.getBytes(2)),
                            row.getBytes(3) == null ? null : uuid(row.getBytes(3))));
            for (Intent intent : pending) {
                try { publish(intent); }
                catch (RuntimeException failure) {
                    jdbc.update("""
                            UPDATE iam_individual_graph_intent SET attempts=LEAST(attempts+1,1000000),
                              next_attempt_at=TIMESTAMPADD(SECOND,LEAST(300,5*(attempts+1)),UTC_TIMESTAMP(6))
                            WHERE snapshot_id=? AND applied_at IS NULL
                            """, intent.snapshot());
                    metrics.counter("authorization.individual.projection", "outcome", "failed").increment();
                }
            }
        } catch (org.springframework.dao.DataAccessException failure) {
            metrics.counter("authorization.individual.projection", "outcome", "unavailable").increment();
        }
    }

    /** @param intent immutable, already committed source generation */
    private void publish(Intent intent) {
        List<Grant> grants = jdbc.query("""
                SELECT authority_id,category_granted,local_granted FROM iam_individual_graph_authority
                WHERE snapshot_id=? ORDER BY authority_id LIMIT 65
                """, (row, index) -> new Grant(uuid(row.getBytes(1)), row.getBoolean(2), row.getBoolean(3)), intent.snapshot());
        if (grants.isEmpty() || grants.size() > 64) throw new IllegalStateException("Incomplete personal capability intent.");
        List<RelationshipUpdate> updates = new ArrayList<>();
        if (intent.group() != null) updates.add(new SpiceDbRelationship("individual_group", intent.group().toString(),
                "participant", "account", intent.account().toString()).update(RelationshipUpdate.Operation.OPERATION_TOUCH));
        for (Grant grant : grants) {
            if (grant.category()) updates.add(tuple(intent, grant.authority(), "category_grantee"));
            if (grant.local()) updates.add(tuple(intent, grant.authority(), "local_grantee"));
        }
        if (updates.isEmpty()) throw new IllegalStateException("Empty personal capability intent.");
        String token = null;
        for (int offset = 0; offset < updates.size(); offset += writer.maxBatchSize())
            token = writer.writeRelationships(updates.subList(offset, Math.min(offset + writer.maxBatchSize(), updates.size())));
        jdbc.update("""
                UPDATE iam_individual_graph_intent SET applied_at=?,zed_token=?,attempts=0
                WHERE snapshot_id=? AND applied_at IS NULL
                """, Timestamp.from(clock.instant()), token, intent.snapshot());
        metrics.counter("authorization.individual.projection", "outcome", "applied").increment();
    }

    /** @param intent source generation @param authority exact stable UUID @param relation schema-owned layer @return idempotent tuple touch */
    private static RelationshipUpdate tuple(Intent intent, UUID authority, String relation) {
        return new SpiceDbRelationship("individual_capability", intent.snapshot() + "_" + authority, relation,
                "account", intent.account().toString()).update(RelationshipUpdate.Operation.OPERATION_TOUCH);
    }

    /** @param id compact MySQL UUID @return domain identity */
    private static UUID uuid(byte[] id) { java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(id); return new UUID(buffer.getLong(), buffer.getLong()); }
    private record Intent(String snapshot, UUID account, UUID group) { }
    private record Grant(UUID authority, boolean category, boolean local) { }
}
