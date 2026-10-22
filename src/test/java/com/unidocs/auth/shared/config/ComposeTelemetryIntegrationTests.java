package com.unidocs.auth.shared.config;

import com.unidocs.auth.MySqlIntegrationTest;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.micrometer.tracing.test.autoconfigure.AutoConfigureTracing;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/** Opt-in acceptance test against existing Compose Filebeat and APM infrastructure. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTracing
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@EnabledIfEnvironmentVariable(named = "AUTH_TEST_ELASTIC_ENDPOINT", matches = ".+")
class ComposeTelemetryIntegrationTests extends MySqlIntegrationTest {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final JsonMapper json = JsonMapper.builder().build();
    @LocalServerPort int port;

    @DynamicPropertySource
    static void telemetryProperties(DynamicPropertyRegistry registry) {
        required("AUTH_TEST_DB_URL");
        registry.add("management.tracing.export.otlp.enabled", () -> true);
        registry.add("management.tracing.sampling.probability", () -> 1.0);
        registry.add("management.opentelemetry.tracing.export.otlp.endpoint", () -> required("AUTH_TEST_APM_ENDPOINT"));
        registry.add("management.opentelemetry.tracing.export.otlp.headers.Authorization",
                () -> "Bearer " + required("AUTH_TEST_APM_TOKEN"));
        registry.add("logging.structured.ecs.service.environment", () -> "test");
        registry.add("management.opentelemetry.resource-attributes.deployment.environment.name", () -> "test");
    }

    @Test
    void failedLoginArrivesAsCorrelatedSafeLogsAndApmTransaction() throws Exception {
        String traceId = UUID.randomUUID().toString().replace("-", "");
        String email = "telemetry-" + UUID.randomUUID() + "@example.invalid";
        String password = "Synthetic-secret-" + UUID.randomUUID();
        String body = json.writeValueAsString(Map.of("email", email, "password", password));
        HttpRequest login = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/v1/auth/login"))
                .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json")
                .header("traceparent", "00-" + traceId + "-00f067aa0ba902b7-01")
                .header("X-User-Id", "forged-telemetry-user").header("X-Tenant-Id", "forged-telemetry-tenant")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        HttpResponse<String> response = client.send(login, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(401);
        String requestId = response.headers().firstValue("X-Request-Id").orElseThrow();
        assertThat(requestId).isNotBlank();

        await().pollInterval(Duration.ofSeconds(2)).atMost(Duration.ofSeconds(60)).untilAsserted(() -> {
            JsonNode hits = search(traceId);
            java.util.Set<String> completedSpanIds = new java.util.HashSet<>();
            java.util.Set<String> transactionIds = new java.util.HashSet<>();
            boolean completed = false;
            boolean failedLogin = false;
            boolean transaction = false;
            for (JsonNode hit : hits) {
                JsonNode source = hit.path("_source");
                assertThat(field(source, "trace.id").asText()).isEqualTo(traceId);
                String index = hit.path("_index").asText();
                if (index.contains("filebeat-")) {
                    assertThat(field(source, "http.request.id").asText()).isEqualTo(requestId);
                    String action = field(source, "event.action").asText();
                    completed |= "http.request.completed".equals(action);
                    if ("http.request.completed".equals(action)) {
                        completedSpanIds.add(field(source, "span.id").asText());
                    }
                    failedLogin |= "auth.login.failed".equals(action);
                }
                if (index.contains("traces-apm")) {
                    transactionIds.add(field(source, "transaction.id").asText());
                    transaction |= "transaction".equals(field(source, "processor.event").asText())
                            && "request".equals(field(source, "transaction.type").asText());
                }
            }
            String serialized = hits.toString();
            assertThat(serialized.contains(email) || serialized.contains(password)
                    || serialized.contains(required("AUTH_TEST_APM_TOKEN"))
                    || serialized.contains(required("AUTH_TEST_ELASTIC_PASSWORD"))
                    || serialized.contains("forged-telemetry-user") || serialized.contains("forged-telemetry-tenant"))
                    .as("indexed telemetry excludes credentials, export secrets and spoofed identity").isFalse();
            assertThat(completed).as("indexed HTTP completion diagnostic").isTrue();
            assertThat(failedLogin).as("indexed failed-login diagnostic").isTrue();
            assertThat(transaction).as("exported APM HTTP transaction").isTrue();
            assertThat(completedSpanIds.stream().anyMatch(id -> !id.isBlank() && transactionIds.contains(id)))
                    .as("HTTP diagnostic span matches exported APM transaction ID").isTrue();
        });
    }

    private JsonNode search(String traceId) throws Exception {
        String credentials = required("AUTH_TEST_ELASTIC_USERNAME") + ":" + required("AUTH_TEST_ELASTIC_PASSWORD");
        String authorization = "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        String endpoint = required("AUTH_TEST_ELASTIC_ENDPOINT").replaceAll("/+$", "");
        HttpRequest search = HttpRequest.newBuilder(URI.create(endpoint
                        + "/filebeat-*,traces-apm*/_search?ignore_unavailable=true"))
                .timeout(Duration.ofSeconds(5)).header("Authorization", authorization)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"size\":100,\"query\":{\"term\":{\"trace.id\":\""
                        + traceId + "\"}}}")).build();
        HttpResponse<String> response = client.send(search, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as("Elasticsearch acceptance search status").isEqualTo(200);
        return json.readTree(response.body()).path("hits").path("hits");
    }

    private static JsonNode field(JsonNode source, String name) {
        if (source.has(name)) {
            return source.path(name);
        }
        JsonNode value = source;
        for (String component : name.split("\\.")) {
            value = value.path(component);
        }
        return value;
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Compose telemetry acceptance requires " + name);
        }
        return value;
    }
}

