package com.unidocs.auth.registration;

import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.registration.api.RegistrationCompletionRequest;
import com.unidocs.auth.registration.api.RegistrationRequest;
import com.unidocs.auth.registration.api.RegistrationResponse;
import com.unidocs.auth.registration.api.VerificationRequest;
import com.unidocs.auth.registration.application.RegistrationProvisioningService;
import com.unidocs.auth.registration.application.RegistrationService;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.sdk.trace.ReadableSpan;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.micrometer.tracing.test.autoconfigure.AutoConfigureTracing;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

/** Uses the externally stopped Compose telemetry receiver and isolated test database. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "auth.outbox.enabled=false")
@AutoConfigureTracing
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@EnabledIfEnvironmentVariable(named = "AUTH_TEST_TELEMETRY_OUTAGE", matches = "true")
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
@ExtendWith(OutputCaptureExtension.class)
class TelemetryOutageIntegrationTests extends MySqlIntegrationTest {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final JsonMapper json = JsonMapper.builder().build();
    @LocalServerPort int port;
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired SdkTracerProvider tracerProvider;
    @Autowired OtlpHttpSpanExporter exporter;

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
    void receiverOutagePreservesAuthenticationReadinessAndDurableAudit(CapturedOutput output) throws Exception {
        String email = "outage-" + UUID.randomUUID() + "@example.invalid";
        String password = "Synthetic-outage-secret-" + UUID.randomUUID();
        RegistrationResponse pending = registrations.register(new RegistrationRequest("Outage Test", email, password));
        String proof = delivery.tokens.get(pending.id());
        registrations.verify(pending.id(), new VerificationRequest(proof));
        provisioning.complete(pending.id(), new RegistrationCompletionRequest(proof));

        Span probe = tracerProvider.get("compose.telemetry.outage").spanBuilder("receiver-outage-probe").startSpan();
        probe.end();
        assertThat(probe instanceof ReadableSpan).as("real SDK span available for outage probe").isTrue();
        assertThat(exporter.export(List.of(((ReadableSpan) probe).toSpanData()))
                .join(5, TimeUnit.SECONDS).isSuccess()).as("stopped receiver rejects real OTLP export").isFalse();

        HttpResponse<String> login = request("POST", "/api/v1/auth/login",
                json.writeValueAsString(Map.of("email", email, "password", password)), null);
        assertThat(login.statusCode()).isEqualTo(200);
        JsonNode tokens = json.readTree(login.body());
        String accessToken = tokens.path("accessToken").asText();
        String refreshToken = tokens.path("refreshToken").asText();
        assertThat(accessToken.isBlank()).as("successful login issues an access token").isFalse();
        assertThat(refreshToken.isBlank()).as("successful login issues a refresh token").isFalse();
        assertThat(request("GET", "/api/v1/me", null, accessToken).statusCode()).isEqualTo(200);
        HttpResponse<String> logout = request("POST", "/api/v1/auth/logout", null, accessToken);
        assertThat(logout.statusCode()).isEqualTo(204);
        assertThat(request("GET", "/api/v1/me", null, accessToken).statusCode()).isEqualTo(401);
        HttpResponse<String> failed = request("POST", "/api/v1/auth/login",
                json.writeValueAsString(Map.of("email", "unknown-" + UUID.randomUUID() + "@example.invalid",
                        "password", password)), null);
        assertThat(failed.statusCode()).isEqualTo(401);
        assertThat(request("GET", "/actuator/health/readiness", null, null).statusCode()).isEqualTo(200);

        JsonNode loginAudit = audit("LOGIN_SUCCEEDED", "auth.login.succeeded", login, "SUCCESS");
        JsonNode logoutAudit = audit("SESSION_REVOKED", "auth.logout.completed", logout, "SUCCESS");
        JsonNode failedAudit = audit("LOGIN_FAILED", "auth.login.failed", failed, "FAILURE");
        assertThat(loginAudit.path("sessionId").asText()).isEqualTo(tokens.path("sessionId").asText());
        assertThat(logoutAudit.path("sessionId").asText()).isEqualTo(tokens.path("sessionId").asText());
        assertThat(failedAudit.path("actorType").asText()).isEqualTo("UNKNOWN");
        assertThat(failedAudit.path("actorId").isNull()).isTrue();
        String envelopes = loginAudit.toString() + logoutAudit + failedAudit;
        assertThat(envelopes.contains(email) || envelopes.contains(password) || envelopes.contains(proof)
                || envelopes.contains(accessToken) || envelopes.contains(refreshToken)
                || envelopes.contains(required("AUTH_TEST_APM_TOKEN")))
                .as("durable audit envelopes exclude credentials and telemetry secrets").isFalse();
        String diagnostics = output.getAll();
        assertThat(diagnostics.contains(email) || diagnostics.contains(password) || diagnostics.contains(proof)
                || diagnostics.contains(accessToken) || diagnostics.contains(refreshToken)
                || diagnostics.contains(required("AUTH_TEST_APM_TOKEN")))
                .as("outage diagnostics exclude credentials and telemetry secrets").isFalse();
    }

    private JsonNode audit(String databaseType, String envelopeType, HttpResponse<String> response, String outcome) {
        String requestId = response.headers().firstValue("X-Request-Id").orElseThrow();
        String envelopeText = jdbc.queryForObject(
                "SELECT envelope FROM security_audit_event WHERE event_type=? AND JSON_UNQUOTE(JSON_EXTRACT(envelope,'$.requestId'))=?",
                String.class, databaseType, requestId);
        JsonNode envelope = json.readTree(envelopeText);
        assertThat(envelope.path("schemaVersion").asInt()).isEqualTo(1);
        assertThat(envelope.path("eventType").asText()).isEqualTo(envelopeType);
        assertThat(envelope.path("outcome").asText()).isEqualTo(outcome);
        assertThat(envelope.path("requestId").asText()).isEqualTo(requestId);
        assertThat(envelope.path("traceId").asText()).matches("[0-9a-f]{32}");
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM outbox_event o JOIN security_audit_event a ON a.id=o.id
                WHERE a.event_type=? AND JSON_UNQUOTE(JSON_EXTRACT(a.envelope,'$.requestId'))=?
                  AND o.aggregate_type='SECURITY_AUDIT' AND o.aggregate_id=a.id AND o.aggregate_version=1
                  AND o.status='PENDING' AND o.event_type='SECURITY_AUDIT_RECORDED'
                  AND o.payload=a.envelope
                """, Integer.class, databaseType, requestId)).isEqualTo(1);
        return envelope;
    }

    private HttpResponse<String> request(String method, String path, String body, String token) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .timeout(Duration.ofSeconds(10)).header("traceparent",
                        "00-" + UUID.randomUUID().toString().replace("-", "") + "-00f067aa0ba902b7-01");
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Compose telemetry outage test requires " + name);
        }
        return value;
    }
}

