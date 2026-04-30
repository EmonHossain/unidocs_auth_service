package com.unidocs.auth.security.spicedb;

import io.micrometer.core.instrument.MeterRegistry;
import io.grpc.StatusRuntimeException;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

/** Bounded outbox-fenced synchronization loop; source mutations mark durable state in their transaction. */
final class SpiceDbOrganizationSyncWorker {
    private static final Logger LOG = LoggerFactory.getLogger(SpiceDbOrganizationSyncWorker.class);
    private final SpiceDbOrganizationSyncService syncService;
    private final SpiceDbRelationshipWriter relationshipWriter;
    private final Clock clock;
    private final MeterRegistry metrics;

    SpiceDbOrganizationSyncWorker(SpiceDbOrganizationSyncService syncService,
            SpiceDbRelationshipWriter relationshipWriter, Clock clock,
            MeterRegistry metrics) {
        this.syncService = syncService;
        this.relationshipWriter = relationshipWriter;
        this.clock = clock;
        this.metrics = metrics;
    }

    @Scheduled(fixedDelayString = "${auth.spicedb.projection.poll-millis:5000}")
    void synchronizeBatch() {
        Instant now = clock.instant();
        syncService.backfillMissingOrganizations(now);
        UUID leaseOwner = UUID.randomUUID();
        for (UUID organization : syncService.claimOrganizationsForSync(leaseOwner, now)) {
            try {
                syncService.synchronizeOrganization(organization, leaseOwner, relationshipWriter, clock.instant());
                metrics.counter("auth.spicedb.organization.sync.processed", "outcome", "attempted").increment();
            } catch (RuntimeException failure) {
                syncService.recordSyncFailure(organization, leaseOwner, clock.instant(), errorCode(failure));
                metrics.counter("auth.spicedb.organization.sync.processed", "outcome", "failed").increment();
                LOG.warn("SpiceDB organization sync failed; retry scheduled (code={})", errorCode(failure));
            }
        }
    }

    private static String errorCode(RuntimeException failure) {
        if (failure instanceof StatusRuntimeException grpcFailure) {
            return "GRPC_" + grpcFailure.getStatus().getCode().name();
        }
        String name = failure.getClass().getSimpleName().toUpperCase(java.util.Locale.ROOT);
        return name.replaceAll("[^A-Z0-9_]", "_").substring(0, Math.min(64, name.length()));
    }
}
