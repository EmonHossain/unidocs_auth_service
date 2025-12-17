package com.unidocs.auth.authorization.application;

import io.micrometer.core.instrument.MeterRegistry;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.UUID;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.header.Header;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "auth.authorization.cache", name = {"enabled", "listener-enabled"}, havingValue = "true")
public class OrganizationInvalidationListener {
    private final OrganizationSnapshotStore snapshots;
    private final MeterRegistry metrics;

    public OrganizationInvalidationListener(OrganizationSnapshotStore snapshots, MeterRegistry metrics) {
        this.snapshots = snapshots;
        this.metrics = metrics;
    }

    @KafkaListener(id = "organizationSnapshotInvalidation", topics = "${auth.outbox.topic}",
            groupId = "iam-organization-cache-${auth.authorization.cache.instance-id}",
            properties = {"auto.offset.reset=latest", "enable.auto.commit=false"})
    public void invalidate(ConsumerRecord<String, String> record) {
        // Disposable caches start empty, so a new pod needs only new invalidations, not a history preload.
        try {
            if (!"ORGANIZATION".equals(header(record, "aggregateType"))) return;
            if (!Set.of("ORGANIZATION_CREATED", "ORGANIZATION_MEMBERSHIP_ACTIVATED", "ORGANIZATION_MEMBER_REMOVED", "ORGANIZATION_MEMBER_BLACKLISTED", "ORGANIZATION_MEMBER_RESTORED", "ORGANIZATION_ACCOUNT_PURGED", "ORGANIZATION_ACCOUNT_AVAILABILITY_CHANGED", "ORGANIZATION_GROUP_MEMBERSHIP_CHANGED",
                    "PROFESSIONAL_RESPONSIBILITY_CHANGED","PROFESSIONAL_ACCESS_CHANGED","PROFESSIONAL_ACCOUNT_RECONCILED").contains(header(record, "eventType"))) return;
            UUID organization = UUID.fromString(header(record, "aggregateId"));
            long version = Long.parseLong(header(record, "aggregateVersion"));
            if (version < 1) throw new IllegalArgumentException();
            snapshots.invalidate(organization, version); // Monotonic, repeatable side effects, including Redis outage.
        } catch (IllegalArgumentException failure) {
            metrics.counter("authorization.invalidation", "outcome", "invalid_event").increment();
        }
    }

    private static String header(ConsumerRecord<String, String> record, String name) {
        Header header = record.headers().lastHeader(name);
        if (header == null || header.value() == null || header.value().length > 64) throw new IllegalArgumentException();
        return new String(header.value(), StandardCharsets.UTF_8);
    }
}
