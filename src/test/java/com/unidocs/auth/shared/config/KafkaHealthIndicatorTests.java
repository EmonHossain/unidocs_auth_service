package com.unidocs.auth.shared.config;

import java.util.concurrent.TimeUnit;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.DescribeClusterResult;
import org.apache.kafka.common.KafkaFuture;
import org.apache.kafka.common.errors.TimeoutException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KafkaHealthIndicatorTests {
    @Mock AdminClient admin;
    @Mock DescribeClusterResult cluster;
    @Mock KafkaFuture<String> future;

    @Test
    void reachableBrokerIsHealthyWithoutExposingMetadata() {
        when(admin.describeCluster()).thenReturn(cluster);
        when(cluster.clusterId()).thenReturn(KafkaFuture.completedFuture("internal-cluster-id"));
        Health health = new KafkaHealthIndicator(admin).health();
        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).isEmpty();
    }

    @Test
    void brokerFailureIsUnhealthyWithoutExposingErrors() throws Exception {
        when(admin.describeCluster()).thenReturn(cluster);
        when(cluster.clusterId()).thenReturn(future);
        when(future.get(2, TimeUnit.SECONDS)).thenThrow(new TimeoutException("internal broker details"));
        Health health = new KafkaHealthIndicator(admin).health();
        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).isEmpty();
    }

    @Test
    void interruptedProbePreservesInterruptStatus() throws Exception {
        when(admin.describeCluster()).thenReturn(cluster);
        when(cluster.clusterId()).thenReturn(future);
        when(future.get(2, TimeUnit.SECONDS)).thenThrow(new InterruptedException());
        try {
            assertThat(new KafkaHealthIndicator(admin).health().getStatus()).isEqualTo(Status.DOWN);
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally {
            Thread.interrupted();
        }
    }
}
