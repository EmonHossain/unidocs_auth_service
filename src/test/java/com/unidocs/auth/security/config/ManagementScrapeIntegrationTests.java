package com.unidocs.auth.security.config;

import com.unidocs.auth.MySqlIntegrationTest;
import io.micrometer.core.instrument.MeterRegistry;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.env.Environment;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "auth.management.scrape.enabled=true",
        "management.server.address=127.0.0.1",
        "management.prometheus.metrics.export.enabled=true",
        "management.endpoint.health.probes.add-additional-paths=true"
})
@org.junit.jupiter.api.extension.ExtendWith(org.springframework.boot.test.system.OutputCaptureExtension.class)
class ManagementScrapeIntegrationTests extends MySqlIntegrationTest {
    private static final String TOKEN = "management_test_only_" + "a".repeat(32);
    private final HttpClient client = HttpClient.newHttpClient();
    @LocalServerPort int applicationPort;
    @Autowired Environment environment;
    @Autowired MeterRegistry registry;
    @Autowired com.unidocs.auth.security.jwt.AccessTokens accessTokens;

    @DynamicPropertySource
    static void managementProperties(DynamicPropertyRegistry properties) throws Exception {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            int port = socket.getLocalPort();
            properties.add("management.server.port", () -> port);
        }
        properties.add("auth.management.scrape.token", () -> TOKEN);
    }

    @Test
    void privateScrapeRequiresDedicatedCredentialAndRemainsIsolatedFromApplication(
            org.springframework.boot.test.system.CapturedOutput output) throws Exception {
        int managementPort = environment.getRequiredProperty("local.management.port", Integer.class);
        assertThat(managementPort).isNotEqualTo(applicationPort);
        registry.counter("authentication.login", "outcome", "succeeded").increment();
        String jwt = accessTokens.issue(java.util.UUID.randomUUID(), java.util.UUID.randomUUID());
        assertThat(send(managementPort, "/actuator/prometheus", "Bearer " + jwt, "GET").statusCode()).isEqualTo(401);
        assertThat(send(applicationPort, "/actuator/prometheus", "Bearer " + jwt, "GET").statusCode()).isEqualTo(403);
        assertThat(send(managementPort, "/actuator/prometheus", null, "GET").statusCode()).isEqualTo(401);
        assertThat(send(managementPort, "/actuator/prometheus", "Bearer wrong-token", "GET").statusCode()).isEqualTo(401);
        assertThat(send(managementPort, "/actuator/prometheus", "Basic Zm9vOmJhcg==", "GET").statusCode()).isEqualTo(401);
        HttpResponse<String> scrape = send(managementPort, "/actuator/prometheus", "Bearer " + TOKEN, "GET");
        assertThat(scrape.statusCode()).isEqualTo(200);
        assertThat(scrape.body()).contains("authentication_login_total", "service=\"auth-service\"")
                .doesNotContain(TOKEN, "management_test_only", "prometheus-scraper");
        assertThat(scrape.headers().firstValue("set-cookie")).isEmpty();
        assertThat(send(managementPort, "/actuator/info", "Bearer " + TOKEN, "GET").statusCode()).isEqualTo(403);
        assertThat(send(managementPort, "/actuator/prometheus", "Bearer " + TOKEN, "POST").statusCode()).isEqualTo(403);
        assertThat(send(managementPort, "/api/v1/me", "Bearer " + TOKEN, "GET").statusCode()).isEqualTo(403);
        assertThat(send(applicationPort, "/actuator/prometheus", "Bearer " + TOKEN, "GET").statusCode()).isEqualTo(401);
        assertThat(send(applicationPort, "/api/v1/me", "Bearer " + TOKEN, "GET").statusCode()).isEqualTo(401);
        assertThat(send(managementPort, "/actuator/prometheus", null, "GET").statusCode()).isEqualTo(401);
        assertThat(send(managementPort, "/actuator/health/readiness", null, "GET").statusCode()).isEqualTo(200);
        assertThat(send(applicationPort, "/readyz", null, "GET").statusCode()).isEqualTo(200);
        assertThat(output.getAll()).doesNotContain(TOKEN, jwt);
    }

    private HttpResponse<String> send(int port, String path, String authorization, String method) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .method(method, HttpRequest.BodyPublishers.noBody());
        if (authorization != null) request.header("Authorization", authorization);
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
}