package com.unidocs.auth.shared.config;

import java.time.ZoneOffset;
import java.util.UUID;

import jakarta.servlet.ServletException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.*;

class RequestCorrelationFilterTests {
    @Test
    void asyncHandoffCleansWorkerIdentityWithoutLoggingPrematureCompletion() throws Exception {
        ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger)
                org.slf4j.LoggerFactory.getLogger(RequestCorrelationFilter.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
                new ch.qos.logback.core.read.ListAppender<>();
        java.util.concurrent.ExecutorService worker = java.util.concurrent.Executors.newSingleThreadExecutor();
        appender.start();
        logger.addAppender(appender);
        try {
            long firstThread = worker.submit(() -> {
                MockHttpServletRequest request = new MockHttpServletRequest();
                request.setAsyncSupported(true);
                org.springframework.web.context.request.RequestContextHolder.setRequestAttributes(
                        new org.springframework.web.context.request.ServletRequestAttributes(request));
                try {
                    new RequestCorrelationFilter().doFilter(request, new MockHttpServletResponse(), (req, res) -> {
                        TrustedRequestContext.authenticatedPrincipal(request, UUID.randomUUID());
                        TrustedRequestContext.authorizedOrganization(UUID.randomUUID());
                        assertThat(MDC.get(TrustedRequestContext.USER_ID)).isNotNull();
                        assertThat(MDC.get(TrustedRequestContext.TENANT_ID)).isNotNull();
                        request.startAsync();
                    });
                    assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
                    assertThat(appender.list).isEmpty();
                    return Thread.currentThread().threadId();
                } finally {
                    org.springframework.web.context.request.RequestContextHolder.resetRequestAttributes();
                }
            }).get(5, java.util.concurrent.TimeUnit.SECONDS);
            long secondThread = worker.submit(() -> {
                assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
                new RequestCorrelationFilter().doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(),
                        (req, res) -> {
                            assertThat(MDC.get(TrustedRequestContext.USER_ID)).isNull();
                            assertThat(MDC.get(TrustedRequestContext.TENANT_ID)).isNull();
                        });
                assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
                return Thread.currentThread().threadId();
            }).get(5, java.util.concurrent.TimeUnit.SECONDS);
            assertThat(secondThread).isEqualTo(firstThread);
            assertThat(appender.list).hasSize(1);
            assertThat(fields(appender.list.getFirst())).doesNotContainKeys("user.id", "labels.tenant_id");
        } finally {
            worker.shutdownNow();
            logger.detachAppender(appender);
            appender.stop();
        }
    }

    @Test
    void generatesSafeRequestIdAndCleansMdcEvenOnFailure() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-Request-Id", "untrusted\nvalue");
        assertThatThrownBy(() -> new RequestCorrelationFilter().doFilter(request, response, (req, res) -> {
            assertThat(MDC.get("requestId")).isEqualTo(response.getHeader("X-Request-Id"));
            assertThat(UUID.fromString(MDC.get("requestId"))).isNotNull();
            throw new ServletException("test failure");
        })).isInstanceOf(ServletException.class);
        assertThat(MDC.get("requestId")).isNull();
    }

    @Test
    void restoresExistingMdcContext() throws Exception {
        MDC.put("requestId", "outer");
        try {
            new RequestCorrelationFilter().doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(),
                    (req, res) -> assertThat(MDC.get("requestId")).isNotEqualTo("outer"));
            assertThat(MDC.get("requestId")).isEqualTo("outer");
        } finally {
            MDC.clear();
        }
    }

    @Test
    void recordsSafeCompletionMetadataAndClearsContextBetweenRequests() throws Exception {
        ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger)
                org.slf4j.LoggerFactory.getLogger(RequestCorrelationFilter.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
                new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/accounts/private-id/login");
            request.setQueryString("token=secret-query");
            request.addHeader("Authorization", "Bearer secret-token");
            request.addHeader("Cookie", "refresh=secret-cookie");
            request.addHeader("X-User-Id", "forged-user");
            request.addHeader("X-Tenant-Id", "forged-tenant");
            request.setContent("secret-password".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            RequestCorrelationFilter filter = new RequestCorrelationFilter();
            filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> {
                req.setAttribute(org.springframework.web.servlet.HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE,
                        "/accounts/{accountId}/login");
                ((jakarta.servlet.http.HttpServletResponse) res).setStatus(401);
            });
            ch.qos.logback.classic.spi.ILoggingEvent event = appender.list.getFirst();
            java.util.Map<String, Object> fields = fields(event);
            assertThat(fields).containsEntry("url.path", "/accounts/{accountId}/login")
                    .containsEntry("http.request.method", "POST")
                    .containsEntry("http.response.status_code", 401)
                    .containsEntry("event.outcome", "failure");
            assertThat((Long) fields.get("event.duration")).isGreaterThanOrEqualTo(0L);
            assertThat(fields.toString()).doesNotContain("secret-", "private-id", "forged-");
            assertThat(event.getThrowableProxy()).isNull();
            assertThat(MDC.get("requestId")).isNull();

            filter.doFilter(new MockHttpServletRequest("UNTRUSTED\nMETHOD", "/secret-path"),
                    new MockHttpServletResponse(), (req, res) -> {});
            assertThat(fields(appender.list.get(1))).containsEntry("http.request.method", "OTHER")
                    .containsEntry("event.outcome", "success").doesNotContainKey("url.path");
            assertThat(MDC.get("requestId")).isNull();

            assertThatThrownBy(() -> filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(),
                    (req, res) -> { throw new ServletException("secret-exception"); }))
                    .isInstanceOf(ServletException.class);
            event = appender.list.get(2);
            assertThat(fields(event)).containsEntry("http.response.status_code", 500)
                    .containsEntry("event.outcome", "failure");
            assertThat(event.getThrowableProxy()).isNull();
            assertThat(event.getFormattedMessage()).doesNotContain("secret-exception");
            assertThat(MDC.get("requestId")).isNull();
        } finally {
            logger.detachAppender(appender);
            appender.stop();
        }
    }

    private static java.util.Map<String, Object> fields(ch.qos.logback.classic.spi.ILoggingEvent event) {
        return event.getKeyValuePairs().stream().collect(java.util.stream.Collectors.toMap(
                pair -> pair.key, pair -> pair.value));
    }
    @Test
    void clockUsesUtc() {
        assertThat(new TimeConfiguration().clock().getZone()).isEqualTo(ZoneOffset.UTC);
    }
    @Test
    void acceptsOneCanonicalLowercaseUuidForCorrelation() throws Exception {
        String requestId = "123e4567-e89b-12d3-a456-426614174000";
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("X-Request-Id", requestId);
        new RequestCorrelationFilter().doFilter(request, response, (req, res) -> {
            assertThat(MDC.get("requestId")).isEqualTo(requestId);
            assertThat(response.getHeader("X-Request-Id")).isEqualTo(requestId);
            assertThat(request.getUserPrincipal()).isNull();
        });
        assertThat(MDC.get("requestId")).isNull();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
            "", "malformed", "1-1-1-1-1",
            "123E4567-E89B-12D3-A456-426614174000",
            " 123e4567-e89b-12d3-a456-426614174000",
            "123e4567-e89b-12d3-a456-426614174000 ",
            "123e4567-e89b-12d3-a456-426614174000\r\nforged: value"
    })
    void replacesInvalidRequestIdWithCanonicalUuid(String suppliedRequestId) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Request-Id", suppliedRequestId);
        assertGeneratedRequestId(request, suppliedRequestId);
    }

    @Test
    void replacesOversizedRequestIdWithCanonicalUuid() throws Exception {
        String suppliedRequestId = "a".repeat(8192);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Request-Id", suppliedRequestId);
        assertGeneratedRequestId(request, suppliedRequestId);
    }

    @Test
    void replacesRepeatedRequestIdHeadersEvenWhenValuesMatch() throws Exception {
        String suppliedRequestId = "123e4567-e89b-12d3-a456-426614174000";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Request-Id", suppliedRequestId);
        request.addHeader("X-Request-Id", suppliedRequestId);
        assertGeneratedRequestId(request, suppliedRequestId);
    }

    @Test
    void generatesDifferentRequestIdsForIndependentRequests() throws Exception {
        MockHttpServletResponse firstResponse = new MockHttpServletResponse();
        MockHttpServletResponse secondResponse = new MockHttpServletResponse();
        RequestCorrelationFilter filter = new RequestCorrelationFilter();
        filter.doFilter(new MockHttpServletRequest(), firstResponse, (req, res) -> {});
        filter.doFilter(new MockHttpServletRequest(), secondResponse, (req, res) -> {});
        assertThat(firstResponse.getHeader("X-Request-Id"))
                .isNotEqualTo(secondResponse.getHeader("X-Request-Id"));
        assertThat(MDC.get("requestId")).isNull();
    }

    private static void assertGeneratedRequestId(MockHttpServletRequest request, String suppliedRequestId)
            throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        new RequestCorrelationFilter().doFilter(request, response, (req, res) -> {
            String generatedRequestId = response.getHeader("X-Request-Id");
            assertThat(generatedRequestId).isNotEqualTo(suppliedRequestId);
            assertThat(UUID.fromString(generatedRequestId).toString()).isEqualTo(generatedRequestId);
            assertThat(MDC.get("requestId")).isEqualTo(generatedRequestId);
        });
        assertThat(MDC.get("requestId")).isNull();
    }

}
