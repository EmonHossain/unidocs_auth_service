package com.unidocs.auth.shared.config;

import java.util.concurrent.TimeUnit;
import org.apache.kafka.clients.admin.AdminClient;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

/** Checks broker metadata with a bounded wait and never exposes connection details. */
public final class KafkaHealthIndicator implements HealthIndicator {
    private final AdminClient admin;

    public KafkaHealthIndicator(AdminClient admin) {
        this.admin = admin;
    }

    @Override
    public Health health() {
        try {
            admin.describeCluster().clusterId().get(2, TimeUnit.SECONDS);
            return Health.up().build();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return Health.down().build();
        } catch (Exception exception) {
            return Health.down().build();
        }
    }
}
