package com.unidocs.auth.shared.config;

import io.micrometer.common.KeyValues;
import java.util.Set;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.tracing.handler.TracingObservationHandler;
import org.springframework.boot.micrometer.observation.autoconfigure.ObservationHandlerGroup;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.observation.DefaultServerRequestObservationConvention;
import org.springframework.http.server.observation.ServerRequestObservationContext;
import org.springframework.http.server.observation.ServerRequestObservationConvention;

@Configuration(proxyBeanMethods = false)
public class TracingConfiguration {
    private static final Set<String> HTTP_METHODS = Set.of(
            "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH");
    @Bean
    ServerRequestObservationConvention safeServerRequestObservationConvention() {
        return new DefaultServerRequestObservationConvention() {
            @Override
            public KeyValues getHighCardinalityKeyValues(ServerRequestObservationContext context) {
                // Export only the bounded semantic method needed by OTLP receivers, never raw paths or queries.
                String method = context.getCarrier().getMethod();
                return KeyValues.of("http.request.method",
                        method != null && HTTP_METHODS.contains(method) ? method : "_OTHER");
            }
        };
    }

    @Bean
    SafeObservationErrorHandler safeObservationErrors() {
        return new SafeObservationErrorHandler();
    }

    @Bean
    ObservationHandlerGroup safeObservationErrorGroup() {
        return new ObservationHandlerGroup() {
            @Override
            public Class<?> handlerType() {
                return SafeObservationErrorHandler.class;
            }

            @Override
            public int compareTo(ObservationHandlerGroup other) {
                // Boot registers grouped handlers before ungrouped handlers regardless of @Order.
                return TracingObservationHandler.class.isAssignableFrom(other.handlerType()) ? -1 : 0;
            }
        };
    }

    static final class SafeObservationErrorHandler implements ObservationHandler<Observation.Context> {
        @Override
        public boolean supportsContext(Observation.Context context) {
            return true;
        }

        @Override
        public void onError(Observation.Context context) {
            Throwable error = context.getError();
            if (error != null && !(error instanceof SafeObservationFailure)) {
                // Only telemetry context changes; callers still receive the original domain exception.
                context.setError(new SafeObservationFailure(error.getClass().getSimpleName()));
            }
        }
    }

    private static final class SafeObservationFailure extends RuntimeException {
        private SafeObservationFailure(String type) {
            super(type, null, false, false);
        }
    }
}

