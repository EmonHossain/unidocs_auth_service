package com.unidocs.auth.security.ratelimit;

import com.unidocs.auth.RedisIntegrationTest;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class RateLimitIntegrationTests extends RedisIntegrationTest {
    private static final String PREFIX = "auth:test:rate:" + UUID.randomUUID();
    @Autowired StringRedisTemplate redis;
    @Autowired RateLimitService service;
    @Autowired RateLimitProperties properties;
    @Autowired RateLimitKeyResolver keys;
    @Autowired MockMvc mvc;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("auth.rate-limit.enabled", () -> true);
        registry.add("auth.rate-limit.key-prefix", () -> PREFIX);
        registry.add("auth.rate-limit.registration-limit", () -> 3);
        registry.add("auth.rate-limit.login-limit", () -> 3);
        registry.add("auth.rate-limit.refresh-limit", () -> 3);
        registry.add("auth.rate-limit.forgot-password-limit", () -> 3);
        registry.add("auth.rate-limit.reset-password-limit", () -> 3);
        registry.add("auth.rate-limit.verification-limit", () -> 3);
    }

    @AfterEach void cleanup() {
        Set<String> found = redis.keys(PREFIX + "*");
        if (found != null && !found.isEmpty()) redis.delete(found);
    }
    private MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setRemoteAddr(UUID.randomUUID().toString());
        return request;
    }

    @Test void atomicAdmissionBoundsConcurrentRequestsAcrossInstances() throws Exception {
        MockHttpServletRequest request = request();
        RateLimitService second = new RateLimitService(redis, properties, keys, new SimpleMeterRegistry());
        AtomicInteger admitted = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService workers = Executors.newFixedThreadPool(12)) {
            List<Future<?>> results = new ArrayList<>();
            for (int index = 0; index < 30; index++) {
                RateLimitService instance = index % 2 == 0 ? service : second;
                results.add(workers.submit(() -> {
                    try {
                        if (!start.await(10, TimeUnit.SECONDS)) throw new AssertionError("Admission barrier timed out.");
                        instance.check(RateLimitPolicy.LOGIN, request);
                        admitted.incrementAndGet();
                    } catch (RateLimitException expected) {
                        assertThat(expected.retryAfterSeconds()).isBetween(1L, 60L);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw new AssertionError(interrupted);
                    }
                }));
            }
            start.countDown();
            for (Future<?> result : results) result.get(15, TimeUnit.SECONDS);
        }
        assertThat(admitted).hasValue(3);
        assertThat(redis.opsForValue().get(keys.resolve(properties, RateLimitPolicy.LOGIN, request))).isEqualTo("3");
    }

    @Test void endpointPoliciesAndPeersAreIndependent() {
        MockHttpServletRequest request = request();
        for (int index = 0; index < 3; index++) service.check(RateLimitPolicy.LOGIN, request);
        assertThatThrownBy(() -> service.check(RateLimitPolicy.LOGIN, request)).isInstanceOf(RateLimitException.class);
        for (RateLimitPolicy policy : RateLimitPolicy.values()) {
            if (policy != RateLimitPolicy.LOGIN) service.check(policy, request);
        }
        service.check(RateLimitPolicy.LOGIN, request());
    }

    @Test void blockedRequestsDoNotExtendWindowAndExpiredBucketRecovers() throws Exception {
        RateLimitProperties shortWindow = new RateLimitProperties(true, PREFIX, Duration.ofSeconds(1), 1, 1, 1, 1, 1, 1);
        RateLimitService shortService = new RateLimitService(redis, shortWindow, keys, new SimpleMeterRegistry());
        MockHttpServletRequest request = request();
        shortService.check(RateLimitPolicy.LOGIN, request);
        String key = keys.resolve(shortWindow, RateLimitPolicy.LOGIN, request);
        Long initial = redis.getExpire(key, TimeUnit.MILLISECONDS);
        assertThatThrownBy(() -> shortService.check(RateLimitPolicy.LOGIN, request)).isInstanceOf(RateLimitException.class);
        assertThat(redis.getExpire(key, TimeUnit.MILLISECONDS)).isPositive().isLessThanOrEqualTo(initial);
        Thread.sleep(1100);
        shortService.check(RateLimitPolicy.LOGIN, request);
        assertThat(redis.opsForValue().get(key)).isEqualTo("1");
    }

    @Test void malformedRequestsAndForwardingHeadersCannotBypassEarlyAdmission() throws Exception {
        String peer = UUID.randomUUID().toString();
        String[] paths = {"/api/v1/auth/login", "/api/v1/auth/employee-login", "/api/v1/auth/accounts/" + UUID.randomUUID() + "/login"};
        for (String path : paths) {
            mvc.perform(post(path).with(request -> { request.setRemoteAddr(peer); return request; })
                    .header("X-Forwarded-For", UUID.randomUUID()).contentType("application/json").content("{"))
                    .andExpect(status().isBadRequest());
        }
        mvc.perform(post(paths[0]).with(request -> { request.setRemoteAddr(peer); return request; })
                .header("Forwarded", "for=192.0.2.99").header("X-Real-IP", "192.0.2.100")
                .contentType("application/json").content("{"))
                .andExpect(status().isTooManyRequests()).andExpect(header().exists("Retry-After"))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.requestId").exists());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_session", Integer.class)).isZero();
    }

    @Test void allProtectedEndpointFamiliesRejectBeforeBodyParsing() throws Exception {
        String[] paths = {"/api/v1/registrations", "/api/v1/auth/refresh", "/api/v1/auth/forgot-password",
                "/api/v1/auth/reset-password", "/api/v1/registrations/" + UUID.randomUUID() + "/verify"};
        for (String path : paths) {
            String peer = UUID.randomUUID().toString();
            for (int index = 0; index < 3; index++) {
                mvc.perform(post(path).with(request -> { request.setRemoteAddr(peer); return request; })
                        .contentType("application/json").content("{"))
                        .andExpect(status().isBadRequest());
            }
            mvc.perform(post(path).with(request -> { request.setRemoteAddr(peer); return request; })
                    .contentType("application/json").content("{"))
                    .andExpect(status().isTooManyRequests());
        }
    }

    @Test void corruptAndNonExpiringRedisStateFailClosed() {
        MockHttpServletRequest request = request();
        String key = keys.resolve(properties, RateLimitPolicy.LOGIN, request);
        redis.opsForValue().set(key, "bad", Duration.ofMinutes(1));
        assertThatThrownBy(() -> service.check(RateLimitPolicy.LOGIN, request)).isInstanceOf(RateLimitUnavailableException.class);
        redis.opsForValue().set(key, "1");
        assertThatThrownBy(() -> service.check(RateLimitPolicy.LOGIN, request)).isInstanceOf(RateLimitUnavailableException.class);
    }

    @Test void corruptStateReturns503WithoutCreatingSession() throws Exception {
        MockHttpServletRequest request = request();
        redis.opsForValue().set(keys.resolve(properties, RateLimitPolicy.LOGIN, request), "bad", Duration.ofMinutes(1));
        mvc.perform(post("/api/v1/auth/login").with(servlet -> { servlet.setRemoteAddr(request.getRemoteAddr()); return servlet; })
                .contentType("application/json").content("{"))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.status").value(503));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_session", Integer.class)).isZero();
        mvc.perform(get("/.well-known/jwks.json")).andExpect(status().isOk());
    }
}
