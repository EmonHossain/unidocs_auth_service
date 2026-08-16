package com.unidocs.auth.credential.recovery.email;

import com.unidocs.auth.MySqlIntegrationTest;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.tracing.Tracer;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.micrometer.tracing.test.autoconfigure.AutoConfigureTracing;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(properties = "management.tracing.sampling.probability=1.0")
@AutoConfigureTracing
class EmailRecoveryTracingTests extends MySqlIntegrationTest {
    @Autowired ObservationRegistry observations;
    @Autowired Tracer tracer;

    @Test
    void decoratedWorkerPropagatesObservationAndClearsContextWhenReused() throws Exception {
        ThreadPoolTaskExecutor executor = new EmailRecoveryConfiguration().emailRecoveryExecutor();
        assertThat(executor.getCorePoolSize()).isEqualTo(2);
        assertThat(executor.getMaxPoolSize()).isEqualTo(2);
        assertThat(executor.getQueueCapacity()).isEqualTo(100);
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.initialize();
        Observation parent = Observation.createNotStarted("recovery.test", observations).start();
        CompletableFuture<Snapshot> propagated = new CompletableFuture<>();
        CompletableFuture<Snapshot> throwing = new CompletableFuture<>();
        try {
            String traceId;
            try (Observation.Scope ignored = parent.openScope()) {
                traceId = tracer.currentSpan().context().traceId();
                executor.execute(() -> propagated.complete(snapshot()));
                assertThatThrownBy(() -> executor.submit(() -> {
                    throwing.complete(snapshot());
                    throw new IllegalStateException("test failure");
                }).get(10, TimeUnit.SECONDS)).hasCauseInstanceOf(IllegalStateException.class);
            }
            Snapshot first = propagated.get(10, TimeUnit.SECONDS);
            assertThat(first.traceId()).isEqualTo(traceId);
            assertThat(first.mdc()).containsEntry("traceId", traceId);
            assertThat(throwing.get(10, TimeUnit.SECONDS).traceId()).isEqualTo(traceId);
            Snapshot cleaned = executor.getThreadPoolExecutor().submit(this::snapshot).get(10, TimeUnit.SECONDS);
            assertThat(cleaned.threadId()).isEqualTo(first.threadId());
            assertThat(cleaned.traceId()).isNull();
            assertThat(cleaned.mdc()).doesNotContainKeys("traceId", "spanId");
            CompletableFuture<Snapshot> next = new CompletableFuture<>();
            executor.execute(() -> next.complete(snapshot()));
            assertThat(next.get(10, TimeUnit.SECONDS).traceId()).isNull();
        } finally {
            parent.stop();
            executor.shutdown();
        }
    }

    private Snapshot snapshot() {
        Map<String, String> context = MDC.getCopyOfContextMap();
        return new Snapshot(Thread.currentThread().threadId(),
                tracer.currentSpan() == null ? null : tracer.currentSpan().context().traceId(),
                context == null ? Map.of() : Map.copyOf(context));
    }

    record Snapshot(long threadId, String traceId, Map<String, String> mdc) { }
}
