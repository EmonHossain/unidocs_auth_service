package com.unidocs.auth.outbox.application;

import com.unidocs.auth.outbox.persistence.OutboxDispatchRepository;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.ObservationRegistry;
import java.time.Clock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.ProducerListener;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "auth.outbox.enabled", havingValue = "true")
@EnableConfigurationProperties(OutboxProperties.class)
@EnableScheduling
public class OutboxConfiguration {
    @Bean
    KafkaTemplate<String, String> outboxKafkaTemplate(ProducerFactory<String, String> factory, ObservationRegistry observations) {
        KafkaTemplate<String, String> template = new KafkaTemplate<>(factory);
        // Kafka's default LoggingProducerListener can include record keys/payloads on errors.
        // The publisher owns sanitized error codes and bounded outcome metrics instead.
        template.setProducerListener(new ProducerListener<>() { });
        template.setObservationRegistry(observations);
        template.setObservationEnabled(true);
        return template;
    }

    @Bean
    KafkaOutboxTransport outboxTransport(KafkaTemplate<String, String> outboxKafkaTemplate, OutboxProperties properties) {
        return new KafkaOutboxTransport(outboxKafkaTemplate, properties);
    }

    @Bean
    OutboxPublisher outboxPublisher(OutboxDispatchRepository repository, OutboxTransport transport,
            OutboxProperties properties, MeterRegistry metrics, Clock clock) {
        return new OutboxPublisher(repository, transport, properties, metrics, clock);
    }

    @Bean
    @ConditionalOnProperty(name = "auth.outbox.scheduling-enabled", havingValue = "true", matchIfMissing = true)
    ScheduledOutboxPublisher scheduledOutboxPublisher(OutboxPublisher publisher, MeterRegistry metrics) {
        return new ScheduledOutboxPublisher(publisher, metrics);
    }
}
