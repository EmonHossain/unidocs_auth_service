package com.unidocs.auth.shared.config;

import io.micrometer.context.ContextRegistry;
import io.micrometer.context.ContextSnapshotFactory;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.contextpropagation.ObservationThreadLocalAccessor;
import io.micrometer.tracing.handler.DefaultTracingObservationHandler;
import io.micrometer.tracing.otel.bridge.OtelCurrentTraceContext;
import io.micrometer.tracing.otel.bridge.OtelTracer;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;
import org.springframework.core.task.support.ContextPropagatingTaskDecorator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AsyncObservationContextTests {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void propagatesTraceAndObservationAndCleansReusedWorker(boolean fail) throws Exception {
        ObservationRegistry observations = ObservationRegistry.create();
        Map<String, String> originalMdc = MDC.getCopyOfContextMap();
        try (SdkTracerProvider provider = SdkTracerProvider.builder().build();
                ExecutorService worker = Executors.newSingleThreadExecutor()) {
            OtelTracer tracer = new OtelTracer(provider.get("async-context-test"),
                    new OtelCurrentTraceContext(), event -> { });
            observations.observationConfig().observationHandler(new DefaultTracingObservationHandler(tracer));
            ContextRegistry contexts = new ContextRegistry();
            contexts.registerThreadLocalAccessor(new ObservationThreadLocalAccessor(observations));
            ContextPropagatingTaskDecorator decorator = new ContextPropagatingTaskDecorator(
                    ContextSnapshotFactory.builder().contextRegistry(contexts).clearMissing(true).build());
            Observation parent = Observation.start("parent", observations);
            long workerId;
            try {
                workerId = worker.submit(() -> Thread.currentThread().threadId()).get(5, TimeUnit.SECONDS);
                try (Observation.Scope scope = parent.openScope()) {
                    String traceId = tracer.currentSpan().context().traceId();
                    String spanId = tracer.currentSpan().context().spanId();
                    MDC.put("userId", "untrusted-user");
                    MDC.put("requestId", "untrusted-request");
                    MDC.put("authorization", "synthetic-secret");
                    Future<?> task = worker.submit(decorator.decorate(() -> {
                        assertThat(Thread.currentThread().threadId()).isEqualTo(workerId);
                        assertThat(observations.getCurrentObservation()).isSameAs(parent);
                        assertThat(tracer.currentSpan().context().traceId()).isEqualTo(traceId);
                        assertThat(tracer.currentSpan().context().spanId()).isEqualTo(spanId);
                        assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
                        if (fail) {
                            throw new IllegalStateException("synthetic failure");
                        }
                    }));
                    if (fail) {
                        assertThatThrownBy(() -> task.get(5, TimeUnit.SECONDS))
                                .isInstanceOf(ExecutionException.class)
                                .hasCauseInstanceOf(IllegalStateException.class);
                    } else {
                        task.get(5, TimeUnit.SECONDS);
                    }
                    assertThat(observations.getCurrentObservation()).isSameAs(parent);
                    assertThat(tracer.currentSpan().context().traceId()).isEqualTo(traceId);
                    assertThat(MDC.get("authorization")).isEqualTo("synthetic-secret");
                    // Submit a raw task: another decorator could conceal a leaked worker context.
                    worker.submit(() -> {
                        assertThat(Thread.currentThread().threadId()).isEqualTo(workerId);
                        assertThat(observations.getCurrentObservation()).isNull();
                        assertThat(tracer.currentSpan()).isNull();
                        assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
                    }).get(5, TimeUnit.SECONDS);
                }
            } finally {
                parent.stop();
            }
            assertThat(observations.getCurrentObservation()).isNull();
            assertThat(tracer.currentSpan()).isNull();
        } finally {
            MDC.clear();
            if (originalMdc != null) {
                MDC.setContextMap(originalMdc);
            }
        }
    }
}
