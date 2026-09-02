package com.unidocs.auth.outbox.application;

import com.unidocs.auth.MySqlIntegrationTest;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.tracing.Tracer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.micrometer.tracing.test.autoconfigure.AutoConfigureTracing;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.listener.KafkaMessageListenerContainer;
import org.springframework.kafka.listener.MessageListener;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@SpringBootTest(properties = {
        "auth.outbox.enabled=true", "auth.outbox.scheduling-enabled=false",
        "management.tracing.sampling.probability=1.0"
})
@AutoConfigureTracing
@EnabledIfEnvironmentVariable(named = "AUTH_TEST_KAFKA_BOOTSTRAP_SERVERS", matches = ".+")
class OutboxTracingTests extends MySqlIntegrationTest {
    @Autowired KafkaTemplate<String, String> template;
    @Autowired ObservationRegistry observations;
    @Autowired Tracer tracer;

    @DynamicPropertySource
    static void kafkaProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.kafka.bootstrap-servers", () -> System.getenv("AUTH_TEST_KAFKA_BOOTSTRAP_SERVERS"));
    }

    @Test
    void observedProducerAndConsumerPropagateW3cTraceWithoutBaggage() throws Exception {
        String bootstrap = System.getenv("AUTH_TEST_KAFKA_BOOTSTRAP_SERVERS");
        String topic = "auth-tracing-test-" + UUID.randomUUID();
        BlockingQueue<Consumed> received = new LinkedBlockingQueue<>();
        try (AdminClient admin = AdminClient.create(Map.of("bootstrap.servers", bootstrap))) {
            admin.createTopics(java.util.List.of(new NewTopic(topic, 1, (short) 1))).all().get(20, TimeUnit.SECONDS);
            ContainerProperties properties = new ContainerProperties(topic);
            properties.setObservationEnabled(true);
            properties.setObservationRegistry(observations);
            properties.setMessageListener((MessageListener<String, String>) record -> {
                Header parent = record.headers().lastHeader("traceparent");
                received.add(new Consumed(tracer.currentSpan().context().traceId(),
                        tracer.currentSpan().context().spanId(),
                        parent == null ? null : new String(parent.value(), StandardCharsets.UTF_8),
                        record.headers().lastHeader("baggage") != null));
            });
            DefaultKafkaConsumerFactory<String, String> factory = new DefaultKafkaConsumerFactory<>(Map.of(
                    ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap,
                    ConsumerConfig.GROUP_ID_CONFIG, topic,
                    ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest",
                    ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class,
                    ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class));
            KafkaMessageListenerContainer<String, String> consumer = new KafkaMessageListenerContainer<>(factory, properties);
            consumer.setBeanName("tracing-test-consumer");
            try {
                consumer.start();
                await().atMost(Duration.ofSeconds(20)).untilAsserted(() ->
                        assertThat(consumer.getAssignedPartitions()).hasSize(1));
                Observation parent = Observation.createNotStarted("outbox.test", observations).start();
                String traceId;
                try {
                    try (Observation.Scope ignored = parent.openScope()) {
                        traceId = tracer.currentSpan().context().traceId();
                        template.send(topic, "test-key", "test-value").get(20, TimeUnit.SECONDS);
                    }
                } finally {
                    parent.stop();
                }
                Consumed first = received.poll(20, TimeUnit.SECONDS);
                assertThat(first).isNotNull();
                assertThat(first.traceId()).isEqualTo(traceId);
                assertThat(first.traceparent()).matches("00-" + traceId + "-[0-9a-f]{16}-[0-9a-f]{2}");
                assertThat(Integer.parseInt(first.traceparent().split("-")[3], 16) & 1).isEqualTo(1);
                assertThat(first.spanId()).isNotEqualTo(first.traceparent().split("-")[2]);
                assertThat(first.baggagePresent()).isFalse();
                // A later durable outbox publish has no request parent; reused consumer starts a fresh trace.
                template.send(topic, "next-key", "next-value").get(20, TimeUnit.SECONDS);
                Consumed next = received.poll(20, TimeUnit.SECONDS);
                assertThat(next).isNotNull();
                assertThat(next.traceId()).matches("[0-9a-f]{32}").isNotEqualTo(traceId);
                assertThat(next.baggagePresent()).isFalse();
                assertThat(tracer.currentSpan()).isNull();
            } finally {
                consumer.stop();

                admin.deleteTopics(java.util.List.of(topic)).all().get(20, TimeUnit.SECONDS);
            }
        }
    }

    record Consumed(String traceId, String spanId, String traceparent, boolean baggagePresent) { }
}
