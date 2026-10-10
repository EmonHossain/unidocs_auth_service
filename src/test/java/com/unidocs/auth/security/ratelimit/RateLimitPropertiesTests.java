package com.unidocs.auth.security.ratelimit;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;

class RateLimitPropertiesTests {
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"unsafe prefix", "{shared}", "prefix\nsecret"})
    void rejectsUnsafeKeyPrefixes(String prefix) {
        assertThatThrownBy(() -> new RateLimitProperties(true, prefix, Duration.ofMinutes(1), 10, 60, 120, 10, 20, 20))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 1000001})
    void rejectsUnboundedOrDisabledPolicyLimits(int limit) {
        assertThatThrownBy(() -> new RateLimitProperties(true, "auth:rate", Duration.ofMinutes(1), 10, limit, 120, 10, 20, 20))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsMissingOrUnsafeWindows() {
        for (Duration window : new Duration[]{null, Duration.ofMillis(999), Duration.ofHours(25)}) {
            assertThatThrownBy(() -> new RateLimitProperties(true, "auth:rate", window, 10, 60, 120, 10, 20, 20))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
