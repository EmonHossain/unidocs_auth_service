package com.unidocs.auth.registration;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authentication.api.LoginRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.organization.api.OrganizationRequest;
import com.unidocs.auth.organization.api.OrganizationResponse;
import com.unidocs.auth.organization.application.OrganizationService;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.application.RegistrationProvisioningService;
import com.unidocs.auth.registration.application.RegistrationService;
import com.unidocs.auth.shared.config.RequestCorrelationFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import com.unidocs.auth.authorization.application.OrganizationSnapshotStore;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.tomcat.threads.max=1", "server.tomcat.threads.min-spare=1"
})
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
class SecurityDiagnosticContextIntegrationTests extends MySqlIntegrationTest {
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final DiagnosticAppender appender = new DiagnosticAppender();
    private final Logger logger = (Logger) LoggerFactory.getLogger(RequestCorrelationFilter.class);
    @LocalServerPort int port;
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @MockitoSpyBean OrganizationSnapshotStore snapshots;
    private RegistrationCompletionResponse identity;
    private TokenResponse token;

    @BeforeEach void provisionAndCapture() {
        String email = UUID.randomUUID() + "@example.com";
        RegistrationResponse pending = registrations.register(new RegistrationRequest("Diagnostics", email, "test-password-long"));
        String proof = delivery.tokens.get(pending.id());
        registrations.verify(pending.id(), new VerificationRequest(proof));
        identity = provisioning.complete(pending.id(), new RegistrationCompletionRequest(proof));
        token = authentication.login(new LoginRequest(email, "test-password-long"));
        appender.setContext(logger.getLoggerContext());
        appender.start();
        logger.addAppender(appender);
    }
    @AfterEach void stopCapture() { logger.detachAppender(appender); appender.stop(); }

    @Test void signedSubjectWinsOverIdentityAndTenantHeaders() throws Exception {
        HttpResponse<String> response = request("/api/v1/me", Map.of(
                "Authorization", "Bearer " + token.accessToken(), "X-User-Id", UUID.randomUUID().toString(),
                "X-Tenant-Id", UUID.randomUUID().toString(), "X-Organization-Id", UUID.randomUUID().toString()));
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(field(response, "user.id")).isEqualTo(identity.accountId().toString()).isNotEqualTo(identity.userId().toString());
        assertThat(field(response, "labels.tenant_id")).isNull();
    }

    @Test void authorizedOrganizationIsRecordedOnlyForSuccessfulOrganizationAccess() throws Exception {
        OrganizationResponse organization = organizations.create(token.sessionId(), identity.accountId(),
                new OrganizationRequest(identity.accountId(), UUID.randomUUID(), "Diagnostics", "diagnostics", Organization.Type.COMPANY));
        String path = "/api/v1/organizations/" + organization.id() + "?accountId=" + identity.accountId();
        for (int attempt = 0; attempt < 2; attempt++) {
            if (attempt == 1) {
                doReturn(true).when(snapshots).enabled();
                doReturn(Optional.of(organization)).when(snapshots).find(identity.accountId(), organization.id());
            }
            HttpResponse<String> allowed = request(path, Map.of("Authorization", "Bearer " + token.accessToken(),
                    "X-Tenant-Id", UUID.randomUUID().toString()));
            assertThat(allowed.statusCode()).isEqualTo(200);
            assertThat(field(allowed, "labels.tenant_id")).isEqualTo(organization.id().toString());
        }
        verify(snapshots).find(identity.accountId(), organization.id());
        HttpResponse<String> denied = request("/api/v1/organizations/" + organization.id() + "?accountId=" + UUID.randomUUID(),
                Map.of("Authorization", "Bearer " + token.accessToken(), "X-Tenant-Id", organization.id().toString()));
        assertThat(denied.statusCode()).isEqualTo(403);
        assertThat(field(denied, "user.id")).isEqualTo(identity.accountId().toString());
        assertThat(field(denied, "labels.tenant_id")).isNull();
        HttpResponse<String> listing = request("/api/v1/me/organizations?accountId=" + identity.accountId(),
                Map.of("Authorization", "Bearer " + token.accessToken()));
        assertThat(listing.statusCode()).isEqualTo(200);
        assertThat(field(listing, "labels.tenant_id")).isNull();
    }

    @Test void anonymousAndInvalidTokensCannotPopulateIdentityOrLeakPreviousRequest() throws Exception {
        HttpResponse<String> authenticated = request("/api/v1/me", Map.of("Authorization", "Bearer " + token.accessToken()));
        assertThat(field(authenticated, "user.id")).isEqualTo(identity.accountId().toString());
        int firstDot = token.accessToken().indexOf('.');
        int lastDot = token.accessToken().lastIndexOf('.');
        Map<String, Object> claims = new java.util.HashMap<>(
                com.nimbusds.jwt.SignedJWT.parse(token.accessToken()).getJWTClaimsSet().toJSONObject());
        claims.put("sub", UUID.randomUUID().toString());
        claims.put("user.id", "forged-user");
        claims.put("tenant.id", "forged-tenant");
        byte[] payload = tools.jackson.databind.json.JsonMapper.builder().build().writeValueAsBytes(claims);
        String forged = token.accessToken().substring(0, firstDot) + "."
                + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(payload)
                + "." + token.accessToken().substring(lastDot + 1);
        for (Map<String, String> headers : List.of(Map.<String, String>of(), Map.of("Authorization", "Bearer malformed"),
                Map.of("Authorization", "Bearer " + forged))) {
            HttpResponse<String> denied = request("/api/v1/me", headers);
            assertThat(denied.statusCode()).isEqualTo(401);
            assertThat(field(denied, "user.id")).isNull();
            assertThat(field(denied, "labels.tenant_id")).isNull();
        }
        HttpResponse<String> publicRequest = request("/actuator/health/liveness", Map.of());
        assertThat(publicRequest.statusCode()).isEqualTo(200);
        assertThat(field(publicRequest, "user.id")).isNull();
        assertThat(field(publicRequest, "labels.tenant_id")).isNull();
        assertThat(appender.events.stream().map(ILoggingEvent::getThreadName).distinct().toList()).hasSize(1);
    }

    private HttpResponse<String> request(String path, Map<String, String> headers) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .timeout(Duration.ofSeconds(10)).GET();
        headers.forEach(builder::header);
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }
    private Object field(HttpResponse<String> response, String key) {
        String requestId = response.headers().firstValue("X-Request-Id").orElseThrow();
        await().atMost(Duration.ofSeconds(5)).until(() -> appender.events.stream()
                .anyMatch(event -> requestId.equals(event.getMDCPropertyMap().get(RequestCorrelationFilter.REQUEST_ID))));
        ILoggingEvent event = appender.events.stream()
                .filter(candidate -> requestId.equals(candidate.getMDCPropertyMap().get(RequestCorrelationFilter.REQUEST_ID)))
                .findFirst().orElseThrow();
        return event.getKeyValuePairs().stream().filter(pair -> key.equals(pair.key)).map(pair -> pair.value).findFirst().orElse(null);
    }
    private static final class DiagnosticAppender extends AppenderBase<ILoggingEvent> {
        private final List<ILoggingEvent> events = new CopyOnWriteArrayList<>();
        @Override protected void append(ILoggingEvent event) { event.prepareForDeferredProcessing(); events.add(event); }
    }
}


