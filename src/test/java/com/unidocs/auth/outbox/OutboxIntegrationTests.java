package com.unidocs.auth.outbox;

import com.unidocs.auth.KafkaIntegrationTest;
import com.unidocs.auth.outbox.application.KafkaOutboxTransport;
import com.unidocs.auth.outbox.application.OutboxPublisher;
import com.unidocs.auth.outbox.domain.ClaimedOutboxEvent;
import com.unidocs.auth.outbox.persistence.OutboxDispatchRepository;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.errors.TimeoutException;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.*;

@SpringBootTest(properties = {"auth.outbox.enabled=true", "auth.outbox.scheduling-enabled=false", "auth.outbox.send-timeout=5s", "auth.outbox.retry-initial=10s"})
class OutboxIntegrationTests extends KafkaIntegrationTest {
    private static final String TOPIC = "iam-outbox-test-" + UUID.randomUUID();
    private static final Duration LEASE = Duration.ofSeconds(60);
    @Autowired OutboxDispatchRepository dispatch;
    @Autowired OutboxPublisher publisher;
    @Autowired PlatformTransactionManager transactions;
    @MockitoSpyBean KafkaOutboxTransport transport;

    @DynamicPropertySource
    static void outboxTopic(DynamicPropertyRegistry registry) {
        registry.add("auth.outbox.topic", () -> TOPIC);
    }

    @BeforeAll
    static void createTopic() throws Exception {
        try (AdminClient admin = AdminClient.create(Map.of("bootstrap.servers", KAFKA.getBootstrapServers()))) {
            admin.createTopics(List.of(new NewTopic(TOPIC, 3, (short) 1))).all().get(10, TimeUnit.SECONDS);
        }
    }

    @AfterAll
    static void removeTopic() throws Exception {
        try (AdminClient admin = AdminClient.create(Map.of("bootstrap.servers", KAFKA.getBootstrapServers()))) {
            admin.deleteTopics(List.of(TOPIC)).all().get(10, TimeUnit.SECONDS);
        }
    }

    @Test
    void committedEventIsDeliveredOutsideTransactionAndOnlyThenPublished() throws Exception {
        UUID id = insert();
        doAnswer(invocation -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE id=? AND claim_token IS NOT NULL", Integer.class, bytes(id))).isEqualTo(1);
            return invocation.callRealMethod();
        }).when(transport).publish(any());
        publisher.publishBatch();
        assertThat(status(id)).isEqualTo("PUBLISHED");
        assertThat(dispatch.claim(1, LEASE)).isEmpty();
        assertDelivered(id);
    }

    @Test
    void failedSendRemainsPendingAndCanRetrySuccessfully() throws Exception {
        UUID id = insert();
        doThrow(new TimeoutException("sensitive broker information")).when(transport).publish(any());
        publisher.publishBatch();
        assertThat(status(id)).isEqualTo("PENDING");
        assertThat(jdbc.queryForObject("SELECT last_error FROM outbox_event WHERE id=?", String.class, bytes(id))).isEqualTo("KAFKA_PUBLISH_FAILED");
        assertThat(jdbc.queryForObject("SELECT attempts FROM outbox_event WHERE id=?", Integer.class, bytes(id))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT available_at > UTC_TIMESTAMP(6) FROM outbox_event WHERE id=?", Boolean.class, bytes(id))).isTrue();
        assertThat(dispatch.claim(1, LEASE)).isEmpty();
        doCallRealMethod().when(transport).publish(any());
        jdbc.update("UPDATE outbox_event SET available_at=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND WHERE id=?", bytes(id));
        publisher.publishBatch();
        assertThat(status(id)).isEqualTo("PUBLISHED");
        assertThat(jdbc.queryForObject("SELECT attempts FROM outbox_event WHERE id=?", Integer.class, bytes(id))).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT last_error FROM outbox_event WHERE id=?", String.class, bytes(id))).isNull();
        assertDelivered(id);
    }

    @Test
    void expiredReservationIsRecoveredAndOldWorkerIsFenced() {
        UUID id = insert();
        ClaimedOutboxEvent old = dispatch.claim(1, LEASE).getFirst();
        assertThat(dispatch.claim(1, LEASE)).isEmpty();
        jdbc.update("UPDATE outbox_event SET lease_until=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND WHERE id=?", bytes(id));
        assertThat(dispatch.renew(old, LEASE)).isFalse();
        assertThat(dispatch.published(old)).isFalse();
        ClaimedOutboxEvent recovered = dispatch.claim(1, LEASE).getFirst();
        assertThat(recovered.id()).isEqualTo(id);
        assertThat(recovered.claimToken()).isNotEqualTo(old.claimToken());
        assertThat(recovered.attempts()).isEqualTo(2);
        assertThat(dispatch.retry(old, Duration.ofSeconds(1))).isFalse();
        assertThat(dispatch.published(old)).isFalse();
        assertThat(dispatch.published(recovered)).isTrue();
    }

    @Test
    void acknowledgementThenCrashCanDeliverDuplicateWithSameEventIdentity() throws Exception {
        UUID id = insert();
        ClaimedOutboxEvent beforeCrash = dispatch.claim(1, LEASE).getFirst();
        transport.publish(beforeCrash); // Simulate process loss before marking the acknowledged row.
        jdbc.update("UPDATE outbox_event SET lease_until=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND WHERE id=?", bytes(id));
        publisher.publishBatch();
        assertThat(status(id)).isEqualTo("PUBLISHED");
        assertThat(jdbc.queryForObject("SELECT attempts FROM outbox_event WHERE id=?", Integer.class, bytes(id))).isEqualTo(2);
        assertDeliveredCount(id, 2);
    }

    @Test
    void concurrentWorkersClaimDifferentCommittedRowsInBoundedBatches() throws Exception {
        UUID first = insert();
        UUID second = insert();
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
            Future<List<ClaimedOutboxEvent>> a = executor.submit(() -> { start.await(); return dispatch.claim(1, LEASE); });
            Future<List<ClaimedOutboxEvent>> b = executor.submit(() -> { start.await(); return dispatch.claim(1, LEASE); });
            start.countDown();
            List<ClaimedOutboxEvent> aClaim = a.get(10, TimeUnit.SECONDS);
            List<ClaimedOutboxEvent> bClaim = b.get(10, TimeUnit.SECONDS);
            assertThat(aClaim).hasSize(1);
            assertThat(bClaim).hasSize(1);
            assertThat(Set.of(aClaim.getFirst().id(), bClaim.getFirst().id())).containsExactlyInAnyOrder(first, second);
            assertThat(dispatch.claim(1, LEASE)).isEmpty();
        }
    }

    @Test
    void uncommittedEventIsSkippedAndRollbackLeavesNothingToPublish() throws Exception {
        CountDownLatch inserted = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<?> writer = executor.submit(() -> new TransactionTemplate(transactions).executeWithoutResult(status -> {
                insert();
                inserted.countDown();
                try {
                    if (!release.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("Test synchronization expired.");
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(interrupted);
                }
                status.setRollbackOnly();
            }));
            try {
                assertThat(inserted.await(5, TimeUnit.SECONDS)).isTrue();
                assertThat(dispatch.claim(1, LEASE)).isEmpty();
            } finally {
                release.countDown();
            }
            writer.get(10, TimeUnit.SECONDS);
        }
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event", Integer.class)).isZero();
        publisher.publishBatch();
        verifyNoInteractions(transport);
    }

    @Test
    void publisherRejectsCallerDatabaseTransaction() {
        new TransactionTemplate(transactions).executeWithoutResult(status ->
                assertThatThrownBy(publisher::publishBatch).isInstanceOf(IllegalTransactionStateException.class));
        verifyNoInteractions(transport);
    }

    private UUID insert() {
        UUID id = UUID.randomUUID();
        UUID aggregate = UUID.randomUUID();
        String payload = """
                {"eventId":"%s","aggregateId":"%s","aggregateVersion":2,
                 "eventType":"ORGANIZATION_CREATED","occurredAt":"2026-10-02T12:00:00Z"}
                """.formatted(id, aggregate);
        jdbc.update("""
                INSERT INTO outbox_event(id,aggregate_type,aggregate_id,aggregate_version,event_type,payload,
                    status,attempts,created_at,available_at)
                VALUES(?,'ORGANIZATION',?,2,'ORGANIZATION_CREATED',?,'PENDING',0,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))
                """, bytes(id), bytes(aggregate), payload);
        return id;
    }

    private String status(UUID id) {
        return jdbc.queryForObject("SELECT status FROM outbox_event WHERE id=?", String.class, bytes(id));
    }

    private void assertDelivered(UUID id) {
        assertDeliveredCount(id, 1);
    }

    private void assertDeliveredCount(UUID id, int expected) {
        String aggregate = jdbc.queryForObject("SELECT JSON_UNQUOTE(JSON_EXTRACT(payload,'$.aggregateId')) FROM outbox_event WHERE id=?", String.class, bytes(id));
        Map<String, Object> configuration = Map.of(
                ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers(),
                ConsumerConfig.GROUP_ID_CONFIG, "outbox-test-" + UUID.randomUUID(),
                ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest",
                ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
        java.util.concurrent.atomic.AtomicInteger matching = new java.util.concurrent.atomic.AtomicInteger();
        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(configuration, new StringDeserializer(), new StringDeserializer())) {
            consumer.subscribe(List.of(TOPIC));
            await().atMost(Duration.ofSeconds(20)).untilAsserted(() -> {
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofSeconds(1));
                for (ConsumerRecord<String, String> record : records) {
                    String eventId = new String(record.headers().lastHeader("eventId").value(), StandardCharsets.UTF_8);
                    if (eventId.equals(id.toString())) {
                        assertThat(record.key()).isEqualTo("ORGANIZATION:" + aggregate);
                        assertThat(record.value()).contains(id.toString());
                        assertThat(new String(record.headers().lastHeader("aggregateVersion").value(), StandardCharsets.UTF_8)).isEqualTo("2");
                        matching.incrementAndGet();
                    }
                }
                assertThat(matching.get()).isGreaterThanOrEqualTo(expected);
            });
        }
    }
}
