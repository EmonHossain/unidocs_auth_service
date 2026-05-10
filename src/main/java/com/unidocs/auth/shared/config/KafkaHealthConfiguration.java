package com.unidocs.auth.shared.config;

import org.apache.kafka.clients.admin.AdminClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaAdmin;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "management.health.kafka.enabled", havingValue = "true")
public class KafkaHealthConfiguration {
    @Bean(destroyMethod = "close")
    AdminClient kafkaHealthAdminClient(KafkaAdmin admin) {
        return AdminClient.create(admin.getConfigurationProperties());
    }

    @Bean
    KafkaHealthIndicator kafkaHealthIndicator(AdminClient kafkaHealthAdminClient) {
        return new KafkaHealthIndicator(kafkaHealthAdminClient);
    }
}
