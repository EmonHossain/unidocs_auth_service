package com.unidocs.auth.outbox.application;

import com.unidocs.auth.outbox.domain.ClaimedOutboxEvent;
import com.unidocs.auth.outbox.persistence.OutboxDispatchRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OutboxPublisherTests {
    @Mock OutboxDispatchRepository repository;
    @Mock OutboxTransport transport;
    private final OutboxProperties properties = properties();
    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();
    private final Instant now = Instant.parse("2026-10-02T12:00:00Z");
    private final ClaimedOutboxEvent event = new ClaimedOutboxEvent(UUID.randomUUID(), "ORGANIZATION",
            UUID.randomUUID(), 2, "ORGANIZATION_CREATED", "sensitive-payload", now, 1, UUID.randomUUID());
    private OutboxPublisher publisher;

    @BeforeEach
    void configure() {
        publisher = new OutboxPublisher(repository, transport, properties, metrics, Clock.fixed(now, ZoneOffset.UTC));
    }

    private void claimed() {
        when(repository.pendingCount()).thenReturn(3L);
        when(repository.oldestPending()).thenReturn(Optional.of(now.minusSeconds(7)));
        when(repository.claim(20, Duration.ofSeconds(60))).thenReturn(List.of(event));
    }

    @Test
    void acknowledgementPrecedesCompletion() throws Exception {
        claimed();
        when(repository.renew(event, properties.leaseDuration())).thenReturn(true);
        when(repository.published(event)).thenReturn(true);
        publisher.publishBatch();
        org.mockito.InOrder order = inOrder(repository, transport);
        order.verify(repository).pendingCount();
        order.verify(repository).oldestPending();
        order.verify(repository).claim(20, properties.leaseDuration());
        order.verify(repository).renew(event, properties.leaseDuration());
        order.verify(transport).publish(event);
        order.verify(repository).published(event);
        assertThat(metrics.get("outbox.delivery").tag("outcome", "published").counter().count()).isEqualTo(1);
        assertThat(metrics.get("outbox.oldest.pending.age.seconds").gauge().value()).isEqualTo(7);
        assertThat(metrics.get("outbox.pending.count").gauge().value()).isEqualTo(3);
    }

    @Test
    void failureSchedulesRetryWithoutAcknowledgingEvent() throws Exception {
        claimed();
        when(repository.renew(event, properties.leaseDuration())).thenReturn(true);
        doThrow(new IllegalStateException("sensitive Kafka error")).when(transport).publish(event);
        when(repository.retry(event, Duration.ofSeconds(1))).thenReturn(true);
        publisher.publishBatch();
        verify(repository).retry(event, Duration.ofSeconds(1));
        verify(repository, never()).published(any());
        assertThat(metrics.get("outbox.delivery").tag("outcome", "retry").counter().count()).isEqualTo(1);
    }

    @Test
    void expiredClaimCannotSend() {
        claimed();
        when(repository.renew(event, properties.leaseDuration())).thenReturn(false);
        publisher.publishBatch();
        verifyNoInteractions(transport);
        verify(repository, never()).published(any());
    }

    @Test
    void lostClaimAfterAcknowledgementDoesNotCountAsPublished() throws Exception {
        claimed();
        when(repository.renew(event, properties.leaseDuration())).thenReturn(true);
        when(repository.published(event)).thenReturn(false);
        publisher.publishBatch();
        assertThat(metrics.get("outbox.delivery").tag("outcome", "lease_lost").counter().count()).isEqualTo(1);
        assertThat(metrics.find("outbox.delivery").tag("outcome", "published").counter()).isNull();
    }

    @Test
    void databaseCompletionFailureLeavesReservationForRecovery() {
        claimed();
        when(repository.renew(event, properties.leaseDuration())).thenReturn(true);
        when(repository.published(event)).thenThrow(new IllegalStateException("database unavailable"));
        assertThatThrownBy(publisher::publishBatch).isInstanceOf(IllegalStateException.class);
        verify(repository, never()).retry(any(), any());
    }

    @Test
    void interruptionKeepsLeaseAndPreservesThreadStatus() throws Exception {
        claimed();
        when(repository.renew(event, properties.leaseDuration())).thenReturn(true);
        doThrow(new InterruptedException()).when(transport).publish(event);
        try {
            publisher.publishBatch();
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
            verify(repository, never()).published(any());
            verify(repository, never()).retry(any(), any());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void activeTransactionCannotStartDelivery() {
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            assertThatThrownBy(publisher::publishBatch).isInstanceOf(IllegalStateException.class);
            verifyNoInteractions(repository, transport);
        } finally {
            TransactionSynchronizationManager.setActualTransactionActive(false);
        }
    }

    @Test
    void retryBackoffIsCappedAndDiagnosticsRedactPayloads() {
        assertThat(properties.retryDelay(1)).isEqualTo(Duration.ofSeconds(1));
        assertThat(properties.retryDelay(3)).isEqualTo(Duration.ofSeconds(4));
        assertThat(properties.retryDelay(Integer.MAX_VALUE)).isEqualTo(Duration.ofMinutes(5));
        assertThat(event.toString()).doesNotContain(event.payload());
        assertThatThrownBy(() -> new OutboxProperties("..", 101, Duration.ofSeconds(1),
                Duration.ofSeconds(20), Duration.ofSeconds(1), Duration.ofSeconds(10)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void backlogSamplesResetAfterQueueDrainsAndScrapesDoNotQueryDatabase() {
        when(repository.pendingCount()).thenReturn(3L, 0L);
        when(repository.oldestPending()).thenReturn(Optional.of(now.minusSeconds(7)), Optional.empty());
        when(repository.claim(20, properties.leaseDuration())).thenReturn(List.of());

        publisher.publishBatch();
        assertThat(metrics.get("outbox.pending.count").gauge().value()).isEqualTo(3);
        assertThat(metrics.get("outbox.oldest.pending.age.seconds").gauge().value()).isEqualTo(7);
        publisher.publishBatch();
        assertThat(metrics.get("outbox.pending.count").gauge().value()).isZero();
        assertThat(metrics.get("outbox.oldest.pending.age.seconds").gauge().value()).isZero();
        verify(repository, times(2)).pendingCount();
        verify(repository, times(2)).oldestPending();
        verifyNoInteractions(transport);
    }

    @Test
    void unavailableBacklogQueryStopsPollingBeforeClaimingOrPublishing() {
        when(repository.pendingCount()).thenThrow(new IllegalStateException("database unavailable"));
        assertThatThrownBy(publisher::publishBatch).isInstanceOf(IllegalStateException.class);
        verify(repository, never()).claim(anyInt(), any());
        verifyNoInteractions(transport);
    }
    static OutboxProperties properties() {
        return new OutboxProperties("iam.domain-events.v1", 20, Duration.ofSeconds(60),
                Duration.ofSeconds(20), Duration.ofSeconds(1), Duration.ofMinutes(5));
    }
}
