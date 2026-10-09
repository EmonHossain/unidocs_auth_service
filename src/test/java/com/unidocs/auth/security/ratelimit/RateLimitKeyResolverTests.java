package com.unidocs.auth.security.ratelimit;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import static org.assertj.core.api.Assertions.assertThat;

class RateLimitKeyResolverTests {
    private final RateLimitProperties properties = new RateLimitProperties(true, "auth:test:rate", Duration.ofMinutes(1),
            10, 60, 120, 10, 20, 20);
    private final RateLimitKeyResolver resolver = new RateLimitKeyResolver();

    @Test
    void forgedForwardingHeadersCannotChangeSocketPeerBucket() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setRemoteAddr("192.0.2.1");
        String key = resolver.resolve(properties, RateLimitPolicy.LOGIN, request);
        request.addHeader("X-Forwarded-For", "198.51.100.8");
        request.addHeader("Forwarded", "for=198.51.100.9");
        request.addHeader("X-Real-IP", "198.51.100.10");
        assertThat(resolver.resolve(properties, RateLimitPolicy.LOGIN, request)).isEqualTo(key);
        assertThat(key).matches("auth:test:rate:LOGIN:[0-9a-f]{64}").doesNotContain("192.0.2.1");
        assertThat(resolver.resolve(properties, RateLimitPolicy.REFRESH, request)).isNotEqualTo(key);
        request.setRemoteAddr("192.0.2.2");
        assertThat(resolver.resolve(properties, RateLimitPolicy.LOGIN, request)).isNotEqualTo(key);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" "})
    void unknownPeersShareBoundedFallbackBucket(String peer) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(peer);
        MockHttpServletRequest fallback = new MockHttpServletRequest();
        fallback.setRemoteAddr("internal");
        assertThat(resolver.resolve(properties, RateLimitPolicy.LOGIN, request))
                .isEqualTo(resolver.resolve(properties, RateLimitPolicy.LOGIN, fallback));
    }
}
