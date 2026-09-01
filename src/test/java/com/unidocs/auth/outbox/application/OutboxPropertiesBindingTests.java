package com.unidocs.auth.outbox.application;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import static org.assertj.core.api.Assertions.assertThat;

class OutboxPropertiesBindingTests {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(BindingConfiguration.class);

    @Test void bindsEnabledPublisherWithDistinctCustomTopics() {
        contextRunner.withPropertyValues("auth.outbox.enabled=true",
                "auth.outbox.topic=custom.domain-events.v1",
                "auth.outbox.audit-topic=custom.security-audit.v1",
                "auth.outbox.batch-size=30").run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(OutboxProperties.class);
            OutboxProperties properties = context.getBean(OutboxProperties.class);
            assertThat(properties.topic()).isEqualTo("custom.domain-events.v1");
            assertThat(properties.auditTopic()).isEqualTo("custom.security-audit.v1");
            assertThat(properties.batchSize()).isEqualTo(30);
        });
    }

    @Test void bindsDefaultValuesThroughConfigurationPropertiesRegistration() {
        contextRunner.run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(OutboxProperties.class);
            OutboxProperties properties = context.getBean(OutboxProperties.class);
            assertThat(properties.topic()).isEqualTo("iam.domain-events.v1");
            assertThat(properties.auditTopic()).isEqualTo("iam.security-audit.v1");
            assertThat(properties.batchSize()).isEqualTo(20);
            assertThat(properties.leaseDuration()).isEqualTo(Duration.ofSeconds(60));
            assertThat(properties.sendTimeout()).isEqualTo(Duration.ofSeconds(20));
            assertThat(properties.retryInitial()).isEqualTo(Duration.ofSeconds(1));
            assertThat(properties.retryMax()).isEqualTo(Duration.ofMinutes(5));
        });
    }

    @Test void rejectsSharedDomainAndAuditTopicDuringBinding() {
        contextRunner.withPropertyValues("auth.outbox.enabled=true",
                "auth.outbox.topic=shared.events.v1",
                "auth.outbox.audit-topic=shared.events.v1").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasRootCauseInstanceOf(IllegalArgumentException.class)
                    .hasRootCauseMessage("Invalid outbox publisher configuration.");
        });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(OutboxProperties.class)
    static class BindingConfiguration {
    }
}
