package com.unidocs.auth.shared.config;

import com.unidocs.auth.MySqlIntegrationTest;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MetricsIntegrationTests extends MySqlIntegrationTest {
    @LocalServerPort int port;
    @Autowired MeterRegistry registry;
    @Autowired com.unidocs.auth.outbox.persistence.OutboxDispatchRepository outbox;

    @Test
    void pendingBacklogIncludesLeasedAndDelayedRowsButExcludesPublishedRows() {
        for (int index = 0; index < 3; index++) {
            java.util.UUID id = java.util.UUID.randomUUID();
            jdbc.update("""
                    INSERT INTO outbox_event(id,aggregate_type,aggregate_id,aggregate_version,event_type,
                        payload,status,attempts,created_at,available_at,claim_token,lease_until,published_at)
                    VALUES(?,'ORGANIZATION',?,1,'ORGANIZATION_CREATED','{}',?,0,
                        UTC_TIMESTAMP(6),UTC_TIMESTAMP(6)+INTERVAL 1 HOUR,?,
                        IF(?=1,UTC_TIMESTAMP(6)+INTERVAL 1 HOUR,NULL),IF(?=1,UTC_TIMESTAMP(6),NULL))
                    """, com.unidocs.auth.session.persistence.SessionRepository.bytes(id),
                    com.unidocs.auth.session.persistence.SessionRepository.bytes(java.util.UUID.randomUUID()),
                    index == 2 ? "PUBLISHED" : "PENDING",
                    index == 0 ? com.unidocs.auth.session.persistence.SessionRepository.bytes(id) : null,
                    index == 0 ? 1 : 0, index == 2 ? 1 : 0);
        }
        assertThat(outbox.pendingCount()).isEqualTo(2);
    }
    @Test
    void observesDeniedHttpRequestWithDeploymentLabelsAndLatencyBuckets() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        double before = registry.counter("authorization.http.denials", "outcome", "unauthenticated").count();
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(
                URI.create("http://localhost:" + port + "/actuator/prometheus")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(401);
        await().untilAsserted(() -> assertThat(registry.get("authorization.http.denials")
                .tag("outcome", "unauthenticated").counter().count()).isGreaterThan(before));
        Timer timer = registry.get("http.server.requests").tag("status", "401").timer();
        assertThat(timer.getId().getTag("service")).isEqualTo("auth-service");
        assertThat(timer.getId().getTag("environment")).isEqualTo("dev");
        assertThat(timer.takeSnapshot().histogramCounts()).isNotEmpty();
        assertThat(timer.getId().getTags()).noneSatisfy(tag ->
                assertThat(tag.getKey()).isIn("user.id", "requestId", "labels.tenant_id"));
        assertThat(response.body()).doesNotContain("jvm_", "http_server_requests", "secret");
    }
}