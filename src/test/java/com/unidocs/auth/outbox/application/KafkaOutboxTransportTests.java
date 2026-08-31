package com.unidocs.auth.outbox.application;

import com.unidocs.auth.outbox.domain.ClaimedOutboxEvent;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.KafkaTemplate;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class KafkaOutboxTransportTests {
    @Mock KafkaTemplate<String, String> kafka;
    @Captor ArgumentCaptor<ProducerRecord<String, String>> records;

    @Test
    void securityAuditUsesIndependentTopicWithStableHeaders() throws Exception {
        assertDelivery("SECURITY_AUDIT", "iam.security-audit.v1");
    }

    @Test
    void domainEventsRetainExistingTopicAndHeaders() throws Exception {
        assertDelivery("ORGANIZATION", "iam.domain-events.v1");
    }

    @Test
    void configurationRejectsSharedOrInvalidTopics() {
        assertThatThrownBy(() -> properties("same-topic", "same-topic"))
                .isInstanceOf(IllegalArgumentException.class);
        for (String invalid : new String[] {"", ".", "..", "bad topic", "a".repeat(250)}) {
            assertThatThrownBy(() -> properties(invalid, "audit-topic"))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> properties("domain-topic", invalid))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> properties("domain-topic", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void legacyConstructorDefaultsAuditTopic() {
        OutboxProperties properties = new OutboxProperties("domain-topic", 20, Duration.ofSeconds(60),
                Duration.ofSeconds(20), Duration.ofSeconds(1), Duration.ofMinutes(5));
        assertThat(properties.auditTopic()).isEqualTo("iam.security-audit.v1");
    }

    private void assertDelivery(String aggregateType, String topic) throws Exception {
        ClaimedOutboxEvent event = new ClaimedOutboxEvent(UUID.randomUUID(), aggregateType,
                UUID.randomUUID(), 7, "EVENT_TYPE", "{\"schemaVersion\":1}",
                Instant.parse("2026-10-08T12:00:00Z"), 1, UUID.randomUUID());
        when(kafka.send(org.mockito.ArgumentMatchers.<ProducerRecord<String, String>>any())).thenReturn(CompletableFuture.completedFuture(null));
        new KafkaOutboxTransport(kafka, properties("iam.domain-events.v1", "iam.security-audit.v1"))
                .publish(event);
        verify(kafka).send(records.capture());
        ProducerRecord<String, String> record = records.getValue();
        assertThat(record.topic()).isEqualTo(topic);
        assertThat(record.key()).isEqualTo(aggregateType + ":" + event.aggregateId());
        assertThat(record.value()).isEqualTo(event.payload());
        assertHeader(record, "eventId", event.id().toString());
        assertHeader(record, "aggregateType", aggregateType);
        assertHeader(record, "aggregateId", event.aggregateId().toString());
        assertHeader(record, "aggregateVersion", "7");
        assertHeader(record, "version", "7");
        assertHeader(record, "eventType", event.eventType());
        assertHeader(record, "occurredAt", event.createdAt().toString());
        assertThat(record.headers()).hasSize(7);
    }

    private static void assertHeader(ProducerRecord<String, String> record, String name, String expected) {
        assertThat(new String(record.headers().lastHeader(name).value(), StandardCharsets.UTF_8))
                .isEqualTo(expected);
    }

    private static OutboxProperties properties(String topic, String auditTopic) {
        return new OutboxProperties(topic, 20, Duration.ofSeconds(60), Duration.ofSeconds(20),
                Duration.ofSeconds(1), Duration.ofMinutes(5), auditTopic);
    }
}