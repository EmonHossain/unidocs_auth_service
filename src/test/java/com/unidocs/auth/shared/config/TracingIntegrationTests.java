package com.unidocs.auth.shared.config;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import com.unidocs.auth.MySqlIntegrationTest;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.sdk.trace.SpanProcessor;
import io.opentelemetry.sdk.trace.ReadWriteSpan;
import io.opentelemetry.sdk.trace.ReadableSpan;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.context.Context;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.http.server.observation.ServerRequestObservationContext;
import io.opentelemetry.api.common.AttributeKey;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.logging.logback.StructuredLogEncoder;
import org.springframework.boot.micrometer.tracing.test.autoconfigure.AutoConfigureTracing;
import org.springframework.boot.micrometer.tracing.opentelemetry.autoconfigure.SdkTracerProviderBuilderCustomizer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.test.annotation.DirtiesContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.tomcat.threads.max=1", "server.tomcat.threads.min-spare=1",
        "management.tracing.sampling.probability=1.0",
        "management.tracing.export.otlp.enabled=true",
        "management.opentelemetry.tracing.export.otlp.endpoint=http://127.0.0.1:1/v1/traces",
        "management.opentelemetry.tracing.export.otlp.timeout=100ms"
})
@AutoConfigureTracing
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@Import(TracingIntegrationTests.CleanupProbeConfiguration.class)
class TracingIntegrationTests extends MySqlIntegrationTest {
    private static final String TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";
    private static final String PARENT_SPAN_ID = "00f067aa0ba902b7";
    private static final String TRACEPARENT = "00-" + TRACE_ID + "-" + PARENT_SPAN_ID + "-01";
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final DiagnosticAppender appender = new DiagnosticAppender();
    private final Logger logger = (Logger) LoggerFactory.getLogger(RequestCorrelationFilter.class);
    @LocalServerPort int port;
    @Autowired Environment environment;
    @Autowired CleanupProbe cleanup;
    @Autowired SdkTracerProvider tracerProvider;
    @Autowired OtlpHttpSpanExporter exporter;
    @Autowired ObservationRegistry observationRegistry;
    @Autowired RecordingSpans spans;

    @BeforeEach
    void captureDiagnostics() {
        cleanup.requests.clear();
        spans.completed.clear();
        appender.events.clear();
        appender.setContext(logger.getLoggerContext());
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void stopCapture() {
        logger.detachAppender(appender);
        appender.stop();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"})
    void canonicalMethodAttributesExcludeRequestSecrets(String method) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/secret-path");
        request.setQueryString("password=secret-password");
        request.addHeader("Authorization", "Bearer secret-token");
        ServerRequestObservationContext context = new ServerRequestObservationContext(request, new MockHttpServletResponse());
        assertThat(new TracingConfiguration().safeServerRequestObservationConvention()
                .getHighCardinalityKeyValues(context))
                .containsExactly(io.micrometer.common.KeyValue.of("http.request.method", method));
    }

    @ParameterizedTest
    @ValueSource(strings = {"get", "CUSTOM-secret-token", ""})
    void unknownMethodAttributesUseBoundedFallback(String method) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/secret-path");
        ServerRequestObservationContext context = new ServerRequestObservationContext(request, new MockHttpServletResponse());
        assertThat(new TracingConfiguration().safeServerRequestObservationConvention()
                .getHighCardinalityKeyValues(context))
                .containsExactly(io.micrometer.common.KeyValue.of("http.request.method", "_OTHER"));
    }

    @Test
    void w3cParentCorrelatesHttpEcsLogsAndIgnoresCustomIdentityHeaders() throws Exception {
        HttpResponse<String> response = request("/actuator/health/liveness", Map.of(
                "traceparent", TRACEPARENT, "X-Trace-Id", "forged-trace-id",
                "X-User-Id", "forged-user", "X-Tenant-Id", "forged-tenant",
                "baggage", "user.id=forged-user,password=secret-password"));
        assertThat(response.statusCode()).isEqualTo(200);
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(spans.completed.stream()
                .filter(span -> TRACE_ID.equals(span.getTraceId()))
                .map(span -> span.getAttributes().get(AttributeKey.stringKey("http.request.method"))))
                .contains("GET"));
        JsonNode event = diagnostic(response);
        assertThat(event.path("trace.id").asText()).isEqualTo(TRACE_ID);
        assertThat(event.path("span.id").asText()).matches("[0-9a-f]{16}").isNotEqualTo(PARENT_SPAN_ID);
        assertThat(event.path("http.request.id").asText()).isEqualTo(requestId(response)).isNotEqualTo(TRACE_ID);
        assertThat(event.toString()).doesNotContain("forged-trace-id", "forged-user", "forged-tenant", "secret-password");
    }

    @Test
    void malformedTraceparentAndCustomTraceHeaderProduceFreshValidTrace() throws Exception {
        HttpResponse<String> response = request("/actuator/health/liveness", Map.of(
                "traceparent", "00-00000000000000000000000000000000-0000000000000000-01",
                "X-Trace-Id", TRACE_ID));
        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode event = diagnostic(response);
        assertThat(event.path("trace.id").asText()).matches("[0-9a-f]{32}")
                .isNotEqualTo(TRACE_ID).isNotEqualTo("00000000000000000000000000000000");
        assertThat(event.path("span.id").asText()).matches("[0-9a-f]{16}")
                .isNotEqualTo("0000000000000000");
    }

    @Test
    void sequentialRequestsReuseWorkerWithoutLeakingTraceOrRequestMdc() throws Exception {
        HttpResponse<String> first = request("/actuator/health/liveness", Map.of("traceparent", TRACEPARENT));
        HttpResponse<String> second = request("/actuator/health/liveness", Map.of());
        assertThat(diagnostic(first).path("trace.id").asText()).isEqualTo(TRACE_ID);
        assertThat(diagnostic(second).path("trace.id").asText()).matches("[0-9a-f]{32}").isNotEqualTo(TRACE_ID);
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(cleanup.requests).hasSize(2));
        CleanupSnapshot before = cleanup.requests.get(0);
        CleanupSnapshot after = cleanup.requests.get(1);
        assertThat(after.threadId()).isEqualTo(before.threadId());
        for (CleanupSnapshot snapshot : cleanup.requests) {
            assertThat(snapshot.before()).doesNotContainKeys("traceId", "spanId", RequestCorrelationFilter.REQUEST_ID);
            assertThat(snapshot.after()).doesNotContainKeys("traceId", "spanId", RequestCorrelationFilter.REQUEST_ID);
        }
    }

    @Test
    void deniedAuthenticationStillHasW3cCorrelationAndSafeDiagnostics() throws Exception {
        HttpResponse<String> response = request("/api/v1/me?password=secret-password&token=secret-token", Map.of(
                "traceparent", TRACEPARENT, "Authorization", "Bearer secret-jwt", "Cookie", "session=secret-cookie"));
        assertThat(response.statusCode()).isEqualTo(401);
        JsonNode event = diagnostic(response);
        assertThat(event.path("trace.id").asText()).isEqualTo(TRACE_ID);
        assertThat(event.at("/http/response/status_code").asInt()).isEqualTo(401);
        assertThat(event.at("/event/outcome").asText()).isEqualTo("failure");
        assertThat(event.toString()).doesNotContain("secret-password", "secret-token", "secret-jwt", "secret-cookie");
        assertThat(response.body()).doesNotContain("secret-password", "secret-token", "secret-jwt", "secret-cookie");
        await().atMost(Duration.ofSeconds(5)).until(() -> !spans.completed.isEmpty());
        assertThat(spans.completed.toString()).doesNotContain("secret-password", "secret-token", "secret-jwt", "secret-cookie");
    }

    @Test
    void unavailableOtlpReceiverDoesNotBreakHealthOrAuthenticationProcessing() throws Exception {
        assertThat(request("/actuator/health/liveness", Map.of()).statusCode()).isEqualTo(200);
        await().atMost(Duration.ofSeconds(5)).until(() -> !spans.completed.isEmpty());
        assertThat(exporter.export(List.copyOf(spans.completed)).join(5, TimeUnit.SECONDS).isSuccess()).isFalse();
        tracerProvider.forceFlush().join(5, TimeUnit.SECONDS);
        assertThat(request("/actuator/health/liveness", Map.of()).statusCode()).isEqualTo(200);
        HttpResponse<String> denied = request("/api/v1/me", Map.of());
        assertThat(denied.statusCode()).isEqualTo(401);
        assertThat(diagnostic(denied).path("trace.id").asText()).matches("[0-9a-f]{32}");
    }

    @Test
    void observedExceptionRetainsApplicationFailureButExportsOnlySafeClassification() {
        IllegalArgumentException original = new IllegalArgumentException("password=secret-password token=secret-token");
        assertThatThrownBy(() -> Observation.createNotStarted("test.safe.failure", observationRegistry)
                .observe(() -> { throw original; })).isSameAs(original);
        SpanData failure = spans.completed.stream()
                .filter(span -> "test.safe.failure".equals(span.getName())).findFirst().orElseThrow();
        assertThat(failure.toString()).doesNotContain("secret-password", "secret-token");
        assertThat(failure.getStatus().getStatusCode()).isEqualTo(io.opentelemetry.api.trace.StatusCode.ERROR);
    }
    private HttpResponse<String> request(String path, Map<String, String> headers) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .timeout(Duration.ofSeconds(10)).GET();
        headers.forEach(builder::header);
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private String requestId(HttpResponse<String> response) {
        return response.headers().firstValue("X-Request-Id").orElseThrow();
    }

    private JsonNode diagnostic(HttpResponse<String> response) throws Exception {
        String requestId = requestId(response);
        await().atMost(Duration.ofSeconds(5)).until(() -> appender.events.stream()
                .anyMatch(event -> requestId.equals(event.getMDCPropertyMap().get(RequestCorrelationFilter.REQUEST_ID))));
        ILoggingEvent event = appender.events.stream()
                .filter(candidate -> requestId.equals(candidate.getMDCPropertyMap().get(RequestCorrelationFilter.REQUEST_ID)))
                .findFirst().orElseThrow();
        LoggerContext context = new LoggerContext();
        context.putObject(Environment.class.getName(), environment);
        StructuredLogEncoder encoder = new StructuredLogEncoder();
        encoder.setContext(context);
        encoder.setFormat(environment.getRequiredProperty("logging.structured.format.console"));
        try {
            encoder.start();
            return JsonMapper.builder().build().readTree(new String(encoder.encode(event), StandardCharsets.UTF_8));
        } finally {
            encoder.stop();
            context.stop();
        }
    }

    private static final class DiagnosticAppender extends AppenderBase<ILoggingEvent> {
        private final List<ILoggingEvent> events = new CopyOnWriteArrayList<>();

        @Override
        protected void append(ILoggingEvent event) {
            event.prepareForDeferredProcessing();
            events.add(event);
        }
    }

    record CleanupSnapshot(long threadId, Map<String, String> before, Map<String, String> after) { }

    static final class CleanupProbe implements Filter {
        private final List<CleanupSnapshot> requests = new CopyOnWriteArrayList<>();

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            Map<String, String> before = snapshot();
            try {
                chain.doFilter(request, response);
            } finally {
                requests.add(new CleanupSnapshot(Thread.currentThread().threadId(), before, snapshot()));
            }
        }

        private static Map<String, String> snapshot() {
            Map<String, String> context = MDC.getCopyOfContextMap();
            return context == null ? Map.of() : Map.copyOf(context);
        }
    }

    static final class RecordingSpans implements SpanProcessor {
        private final List<SpanData> completed = new CopyOnWriteArrayList<>();
        @Override public void onStart(Context context, ReadWriteSpan span) { }
        @Override public boolean isStartRequired() { return false; }
        @Override public void onEnd(ReadableSpan span) { completed.add(span.toSpanData()); }
        @Override public boolean isEndRequired() { return true; }
    }
    @TestConfiguration(proxyBeanMethods = false)
    static class CleanupProbeConfiguration {
        @Bean RecordingSpans recordingSpans() { return new RecordingSpans(); }
        @Bean SdkTracerProviderBuilderCustomizer captureSpans(RecordingSpans spans) {
            return builder -> builder.addSpanProcessor(spans);
        }

        @Bean CleanupProbe cleanupProbe() { return new CleanupProbe(); }

        @Bean FilterRegistrationBean<CleanupProbe> cleanupRegistration(CleanupProbe probe) {
            FilterRegistrationBean<CleanupProbe> registration = new FilterRegistrationBean<>(probe);
            registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
            return registration;
        }
    }
}


