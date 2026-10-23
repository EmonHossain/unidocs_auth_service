package com.unidocs.auth.shared.config;

import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.observation.Observation;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.server.observation.ServerRequestObservationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class MetricsConfigurationTests {
    private final MetricsConfiguration configuration = new MetricsConfiguration();

    @Test
    void rejectsPrivateLabelsAndBoundsRouteSeries() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        try {
            registry.config().meterFilter(configuration.privateMetricTags())
                    .meterFilter(configuration.boundedHttpRoutes());
            for (String key : new String[] {"user.id", "labels.tenant_id", "requestId", "trace_id", "email", "token"}) {
                registry.counter("private.test", key, UUID.randomUUID().toString()).increment();
            }
            assertThat(registry.getMeters()).isEmpty();
            for (int index = 0; index < 110; index++) {
                Timer.builder("http.server.requests").tag("uri", "/route/" + index).register(registry);
            }
            assertThat(registry.getMeters()).hasSize(100);
            registry.counter("authentication.login", "outcome", "failed").increment();
            assertThat(registry.get("authentication.login").counter().count()).isEqualTo(1);
        } finally {
            registry.close();
        }
    }

    @Test
    void countsCompletedDenialsWithoutIdentityOrRawRequestTags() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        try {
            MetricsConfiguration.HttpDenialMetrics handler = configuration.httpDenialMetrics(registry);
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/secret/" + UUID.randomUUID());
            request.addHeader("Authorization", "Bearer secret-token");
            MockHttpServletResponse response = new MockHttpServletResponse();
            ServerRequestObservationContext context = new ServerRequestObservationContext(request, response);
            assertThat(handler.supportsContext(context)).isTrue();
            assertThat(handler.supportsContext(new Observation.Context())).isFalse();
            for (int status : new int[] {200, 400, 401, 403, 403, 500}) {
                response.setStatus(status);
                handler.onStop(context);
            }
            assertThat(registry.get("authorization.http.denials").tag("outcome", "unauthenticated").counter().count()).isEqualTo(1);
            assertThat(registry.get("authorization.http.denials").tag("outcome", "forbidden").counter().count()).isEqualTo(2);
            assertThat(registry.getMeters()).allSatisfy(meter ->
                    assertThat(meter.getId().getTags()).hasSize(1));
        } finally {
            registry.close();
        }
    }
}