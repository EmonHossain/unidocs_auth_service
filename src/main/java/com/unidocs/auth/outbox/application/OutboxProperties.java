package com.unidocs.auth.outbox.application;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("auth.outbox")
public record OutboxProperties(
        @DefaultValue("iam.domain-events.v1") String topic,
        @DefaultValue("20") int batchSize,
        @DefaultValue("60s") Duration leaseDuration,
        @DefaultValue("20s") Duration sendTimeout,
        @DefaultValue("1s") Duration retryInitial,
        @DefaultValue("5m") Duration retryMax,
        @DefaultValue("iam.security-audit.v1") String auditTopic) {
    @ConstructorBinding
    public OutboxProperties {
        if (!validTopic(topic) || !validTopic(auditTopic) || topic.equals(auditTopic)
                || batchSize < 1 || batchSize > 100
                || !between(sendTimeout, Duration.ofMillis(100), Duration.ofMinutes(1))
                || !between(leaseDuration, Duration.ofSeconds(30), Duration.ofHours(1))
                || !between(retryInitial, Duration.ofSeconds(1), Duration.ofHours(1))
                || !between(retryMax, Duration.ofSeconds(1), Duration.ofHours(1))
                || retryInitial.compareTo(retryMax) > 0
                || leaseDuration.compareTo(sendTimeout.plusSeconds(10)) <= 0) {
            throw new IllegalArgumentException("Invalid outbox publisher configuration.");
        }
    }

    public OutboxProperties(String topic, int batchSize, Duration leaseDuration,
            Duration sendTimeout, Duration retryInitial, Duration retryMax) {
        this(topic, batchSize, leaseDuration, sendTimeout, retryInitial, retryMax,
                "iam.security-audit.v1");
    }

    private static boolean validTopic(String topic) {
        return topic != null && topic.matches("[a-zA-Z0-9_-][a-zA-Z0-9._-]{0,248}");
    }
    public Duration retryDelay(int attempts) {
        long multiplier = 1L << Math.min(Math.max(attempts - 1, 0), 20);
        return Duration.ofMillis(Math.min(retryMax.toMillis(), retryInitial.toMillis() * multiplier));
    }

    private static boolean between(Duration value, Duration min, Duration max) {
        return value != null && value.compareTo(min) >= 0 && value.compareTo(max) <= 0;
    }
}
