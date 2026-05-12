package com.unidocs.auth.shared.config;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.core.instrument.config.MeterFilterReply;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import java.util.Set;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.observation.ServerRequestObservationContext;

@Configuration(proxyBeanMethods = false)
public class MetricsConfiguration {
    private static final Set<String> PRIVATE_TAGS = Set.of(
            "user.id", "user_id", "tenant.id", "tenant_id", "labels.tenant_id",
            "requestId", "request_id", "http.request.id", "traceId", "trace_id",
            "spanId", "span_id", "email", "document.id", "document_id",
            "authorization", "token", "password", "otp");

    @Bean
    MeterFilter privateMetricTags() {
        return new MeterFilter() {
            @Override
            public MeterFilterReply accept(Meter.Id id) {
                return id.getTags().stream().anyMatch(tag -> PRIVATE_TAGS.contains(tag.getKey()))
                        ? MeterFilterReply.DENY : MeterFilterReply.NEUTRAL;
            }
        };
    }

    @Bean
    MeterFilter boundedHttpRoutes() {
        return MeterFilter.maximumAllowableTags("http.server.requests", "uri", 100, MeterFilter.deny());
    }

    @Bean
    HttpDenialMetrics httpDenialMetrics(MeterRegistry registry) {
        return new HttpDenialMetrics(registry);
    }

    static final class HttpDenialMetrics implements ObservationHandler<ServerRequestObservationContext> {
        private final MeterRegistry registry;

        HttpDenialMetrics(MeterRegistry registry) {
            this.registry = registry;
        }

        @Override
        public boolean supportsContext(Observation.Context context) {
            return context instanceof ServerRequestObservationContext;
        }

        @Override
        public void onStop(ServerRequestObservationContext context) {
            if (context.getResponse() == null) return;
            int status = context.getResponse().getStatus();
            if (status == 401 || status == 403) {
                registry.counter("authorization.http.denials", "outcome",
                        status == 401 ? "unauthenticated" : "forbidden").increment();
            }
        }
    }
}