package com.unidocs.auth.outbox.application;

import com.unidocs.auth.outbox.domain.ClaimedOutboxEvent;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.springframework.kafka.core.KafkaTemplate;

public class KafkaOutboxTransport implements OutboxTransport {
    private final KafkaTemplate<String, String> kafka;
    private final OutboxProperties properties;

    public KafkaOutboxTransport(KafkaTemplate<String, String> kafka, OutboxProperties properties) {
        this.kafka = kafka;
        this.properties = properties;
    }

    @Override
    public void publish(ClaimedOutboxEvent event) throws Exception {
        String topic = "SECURITY_AUDIT".equals(event.aggregateType()) ? properties.auditTopic() : properties.topic();
        ProducerRecord<String, String> record = new ProducerRecord<>(topic,
                event.aggregateType() + ":" + event.aggregateId(), event.payload());
        header(record, "eventId", event.id().toString());
        header(record, "aggregateType", event.aggregateType());
        header(record, "aggregateId", event.aggregateId().toString());
        header(record, "aggregateVersion", Long.toString(event.aggregateVersion()));
        header(record, "version", Long.toString(event.aggregateVersion()));
        header(record, "eventType", event.eventType());
        header(record, "occurredAt", event.createdAt().toString());
        kafka.send(record).get(properties.sendTimeout().toMillis(), TimeUnit.MILLISECONDS);
    }

    private static void header(ProducerRecord<String, String> record, String name, String value) {
        record.headers().add(name, value.getBytes(StandardCharsets.UTF_8));
    }
}
