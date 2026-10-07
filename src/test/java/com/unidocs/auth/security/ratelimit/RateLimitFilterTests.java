package com.unidocs.auth.security.ratelimit;

import com.unidocs.auth.security.config.SecurityProblemWriter;
import com.unidocs.auth.shared.config.RequestCorrelationFilter;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class RateLimitFilterTests {
    @Test
    void configuredPrefixControlsRequestAdmission() throws Exception {
        RateLimitService customService = mock(RateLimitService.class);
        RateLimitFilter customFilter = new RateLimitFilter(customService,
                new SecurityProblemWriter(JsonMapper.builder().build()),
                new com.unidocs.auth.shared.config.ApiVersionProperties("/services/auth/v2"));
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/services/auth/v2/auth/login");
        customFilter.doFilter(request, new MockHttpServletResponse(), mock(FilterChain.class));
        verify(customService).check(RateLimitPolicy.LOGIN, request);
        clearInvocations(customService);
        for (String path : java.util.List.of("/api/v1/auth/login", "/services/auth/v20/auth/login")) {
            customFilter.doFilter(new MockHttpServletRequest("POST", path), new MockHttpServletResponse(), mock(FilterChain.class));
        }
        verifyNoInteractions(customService);
    }
    private final RateLimitService service = mock(RateLimitService.class);
    private final FilterChain chain = mock(FilterChain.class);
    private final RateLimitFilter filter = new RateLimitFilter(service, new SecurityProblemWriter(JsonMapper.builder().build()));

    @Test
    void admitsProtectedRequestsBeforeContinuingChain() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        org.mockito.InOrder order = inOrder(service, chain);
        order.verify(service).check(RateLimitPolicy.LOGIN, request);
        order.verify(chain).doFilter(request, response);
    }

    @Test
    void bypassesUnprotectedRequests() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        verifyNoInteractions(service);
        verify(chain).doFilter(request, response);
    }

    @Test
    void blockedRequestReturnsCorrelatedProblemWithRetryAfter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/refresh");
        request.setAttribute(RequestCorrelationFilter.REQUEST_ID, "test-request");
        MockHttpServletResponse response = new MockHttpServletResponse();
        doThrow(new RateLimitException(7)).when(service).check(RateLimitPolicy.REFRESH, request);
        filter.doFilter(request, response, chain);
        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getHeader("Retry-After")).isEqualTo("7");
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(response.getContentAsString()).contains("\"requestId\":\"test-request\"", "\"status\":429");
        verifyNoInteractions(chain);
    }

    @Test
    void redisFailureFailsClosed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        doThrow(new RateLimitUnavailableException()).when(service).check(RateLimitPolicy.LOGIN, request);
        filter.doFilter(request, response, chain);
        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getContentAsString()).contains("\"status\":503");
        verifyNoInteractions(chain);
    }
}

