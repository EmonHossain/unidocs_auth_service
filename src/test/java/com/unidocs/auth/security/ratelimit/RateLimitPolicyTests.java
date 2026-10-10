package com.unidocs.auth.security.ratelimit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitPolicyTests {
    @org.junit.jupiter.api.Test
    void configuredPrefixUsesDecodedPathAndExactBoundary() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/services/auth/v2/auth/%6cogin");
        assertThat(RateLimitPolicy.resolve(request, "/services/auth/v2")).isEqualTo(RateLimitPolicy.LOGIN);
        request = new MockHttpServletRequest("POST", "/services/auth/v2/auth/accounts/account/login");
        assertThat(RateLimitPolicy.resolve(request, "/services/auth/v2")).isEqualTo(RateLimitPolicy.LOGIN);
        for (String path : java.util.List.of("/api/v1/auth/login", "/services/auth/v20/auth/login", "/services/auth/v2extra/auth/login")) {
            assertThat(RateLimitPolicy.resolve(new MockHttpServletRequest("POST", path), "/services/auth/v2")).isNull();
        }
    }
    @org.junit.jupiter.api.Test
    void resolvesDecodedServletPathAndEncodedFallback() {
        org.springframework.mock.web.MockHttpServletRequest request = new org.springframework.mock.web.MockHttpServletRequest("POST", "/api/v1/auth/%6cogin");
        org.assertj.core.api.Assertions.assertThat(RateLimitPolicy.resolve(request)).isEqualTo(RateLimitPolicy.LOGIN);
        request.setServletPath("/api/v1/auth/login");
        org.assertj.core.api.Assertions.assertThat(RateLimitPolicy.resolve(request)).isEqualTo(RateLimitPolicy.LOGIN);
    }
    @ParameterizedTest
    @CsvSource({
        "/api/v1/registrations, REGISTRATION",
        "/api/v1/institutes/institute-id/student-admissions, REGISTRATION",
        "/api/v1/institutes/institute-id/student-admissions/admission-id/verify, VERIFICATION",
        "/api/v1/registrations/8a24370c-2d94-4af8-8c34-58d6d859e541/verify, VERIFICATION",
        "/api/v1/registrations/8a24370c-2d94-4af8-8c34-58d6d859e541/complete, VERIFICATION",
        "/api/v1/auth/login, LOGIN",
        "/api/v1/auth/employee-login, LOGIN",
        "/api/v1/auth/accounts/8a24370c-2d94-4af8-8c34-58d6d859e541/login, LOGIN",
        "/api/v1/auth/refresh, REFRESH",
        "/api/v1/auth/forgot-password, FORGOT_PASSWORD",
        "/api/v1/auth/employee-forgot-password, FORGOT_PASSWORD",
        "/api/v1/auth/reset-password, RESET_PASSWORD",
        "/api/v1/auth/employee-reset-password, RESET_PASSWORD"
    })
    void resolvesPublicSecurityEndpoints(String path, RateLimitPolicy expected) {
        assertThat(RateLimitPolicy.resolve(new MockHttpServletRequest("POST", path))).isEqualTo(expected);
    }

    @Test
    void removesOnlyTheActualContextPath() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/iam/api/v1/auth/login");
        request.setContextPath("/iam");
        assertThat(RateLimitPolicy.resolve(request)).isEqualTo(RateLimitPolicy.LOGIN);
    }

    @ParameterizedTest
    @CsvSource({
        "GET, /api/v1/auth/login",
        "OPTIONS, /api/v1/auth/login",
        "POST, /api/v1/auth/logout",
        "POST, /api/v1/auth/login-extra",
        "POST, /api/v1/registrations/id/verify/extra",
        "POST, /api/v1/auth/accounts/id/login/extra",
        "POST, /actuator/health"
    })
    void ignoresUnprotectedRequests(String method, String path) {
        assertThat(RateLimitPolicy.resolve(new MockHttpServletRequest(method, path))).isNull();
    }
}


