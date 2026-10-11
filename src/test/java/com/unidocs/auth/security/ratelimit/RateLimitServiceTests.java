package com.unidocs.auth.security.ratelimit;

import java.time.Duration;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RateLimitServiceTests {
    @Mock private StringRedisTemplate redis;
    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");

    private RateLimitService service(boolean enabled) {
        return new RateLimitService(redis, new RateLimitProperties(enabled, "auth:test:rate", Duration.ofMinutes(1),
                10, 60, 120, 10, 20, 20), new RateLimitKeyResolver(), metrics);
    }

    @Test
    void disabledLimitsDoNotContactRedis() {
        service(false).check(RateLimitPolicy.LOGIN, request);
        verifyNoInteractions(redis);
    }

    @Test
    void allowsAtomicAdmission() {
        when(redis.execute(any(RedisScript.class), anyList(), any(Object[].class))).thenReturn(0L);
        service(true).check(RateLimitPolicy.LOGIN, request);
        verify(redis).execute(any(RedisScript.class), anyList(), eq("60"), eq("60000"));
        assertThat(metrics.get("auth.rate_limit").tag("outcome", "allowed").counter().count()).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(longs = {1, 999, 1000, 1001, 60000})
    void blocksAndRoundsRetryTimeUp(long ttl) {
        when(redis.execute(any(RedisScript.class), anyList(), any(Object[].class))).thenReturn(ttl);
        assertThatThrownBy(() -> service(true).check(RateLimitPolicy.LOGIN, request)).isInstanceOfSatisfying(RateLimitException.class, failure -> assertThat(failure.retryAfterSeconds()).isEqualTo((ttl + 999) / 1000));
        assertThat(metrics.get("auth.rate_limit").tag("outcome", "blocked").counter().count()).isEqualTo(1);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(longs = {-1, 60001, Long.MAX_VALUE})
    void malformedAdmissionFailsClosed(Long result) {
        when(redis.execute(any(RedisScript.class), anyList(), any(Object[].class))).thenReturn(result);
        assertThatThrownBy(() -> service(true).check(RateLimitPolicy.LOGIN, request)).isInstanceOf(RateLimitUnavailableException.class);
        assertThat(metrics.get("auth.rate_limit").tag("outcome", "unavailable").counter().count()).isEqualTo(1);
    }

    @Test
    void outageDetailsAreNotExposed() {
        when(redis.execute(any(RedisScript.class), anyList(), any(Object[].class)))
                .thenThrow(new IllegalStateException("private Redis host password details"));
        assertThatThrownBy(() -> service(true).check(RateLimitPolicy.LOGIN, request))
                .isInstanceOf(RateLimitUnavailableException.class).hasMessageNotContaining("private").hasNoCause();
    }
}

