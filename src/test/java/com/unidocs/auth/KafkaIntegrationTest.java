package com.unidocs.auth;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.kafka.KafkaContainer;
import org.testcontainers.utility.TestcontainersConfiguration;

/** Manual lifecycle preserves the reusable broker; Ryuk owns cleanup in CI. */
public abstract class KafkaIntegrationTest extends MySqlIntegrationTest {
    protected static final KafkaContainer KAFKA = startKafka();

    private static KafkaContainer startKafka() {
        KafkaContainer container = new KafkaContainer("apache/kafka:4.1.2")
                .withReuse(TestcontainersConfiguration.getInstance().environmentSupportsReuse());
        container.start();
        return container;
    }

    @DynamicPropertySource
    static void kafkaProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.kafka.bootstrap-servers", KAFKA::getBootstrapServers);
    }
}
