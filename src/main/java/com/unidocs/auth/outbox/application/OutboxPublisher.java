package com.unidocs.auth.outbox.application;

import com.unidocs.auth.outbox.domain.ClaimedOutboxEvent;
import com.unidocs.auth.outbox.persistence.OutboxDispatchRepository;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Transactional(propagation = Propagation.NEVER)
public class OutboxPublisher {
    private final OutboxDispatchRepository repository;
    private final OutboxTransport transport;
    private final OutboxProperties properties;
    private final MeterRegistry metrics;
    private final Clock clock;
    private final AtomicLong oldestAge;
    private final AtomicLong pendingCount;

    public OutboxPublisher(OutboxDispatchRepository repository, OutboxTransport transport,
            OutboxProperties properties, MeterRegistry metrics, Clock clock) {
        this.repository = repository;
        this.transport = transport;
        this.properties = properties;
        this.metrics = metrics;
        this.clock = clock;
        this.oldestAge = metrics.gauge("outbox.oldest.pending.age.seconds", new AtomicLong());
        this.pendingCount = metrics.gauge("outbox.pending.count", new AtomicLong());
    }

    public void publishBatch() {
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("Outbox delivery cannot run inside a database transaction.");
        }
        pendingCount.set(repository.pendingCount());
        oldestAge.set(repository.oldestPending().map(created ->
                Math.max(0, Duration.between(created, clock.instant()).toSeconds())).orElse(0L));
        for (ClaimedOutboxEvent event : repository.claim(properties.batchSize(), properties.leaseDuration())) {
            if (Thread.currentThread().isInterrupted()) break;
            if (!repository.renew(event, properties.leaseDuration())) {
                outcome("lease_lost");
                continue;
            }
            // The reservation transaction has committed. No database transaction spans Kafka I/O.
            try {
                transport.publish(event);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                break; // Remaining claims become available after their leases expire.
            } catch (Exception failure) {
                outcome(repository.retry(event, properties.retryDelay(event.attempts())) ? "retry" : "lease_lost");
                continue;
            }
            // A DB failure here leaves the lease for recovery, which can deliver a duplicate.
            outcome(repository.published(event) ? "published" : "lease_lost");
        }
    }

    private void outcome(String outcome) {
        metrics.counter("outbox.delivery", "outcome", outcome).increment();
    }
}
