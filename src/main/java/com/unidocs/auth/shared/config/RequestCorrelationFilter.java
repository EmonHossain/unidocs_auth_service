package com.unidocs.auth.shared.config;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerMapping;

@Component
// Inside Boot HTTP observation (+1), before request admission (+10) and security.
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
public class RequestCorrelationFilter extends OncePerRequestFilter {
    public static final String REQUEST_ID = "requestId";
    private static final Logger LOG = LoggerFactory.getLogger(RequestCorrelationFilter.class);
    private static final Set<String> METHODS = Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String requestId = requestId(request);
        String previous = MDC.get(REQUEST_ID);
        String previousUser = MDC.get(TrustedRequestContext.USER_ID);
        String previousTenant = MDC.get(TrustedRequestContext.TENANT_ID);
        TrustedRequestContext.clear(request);
        long started = System.nanoTime();
        boolean failed = true;
        request.setAttribute(REQUEST_ID, requestId);
        response.setHeader("X-Request-Id", requestId);
        MDC.put(REQUEST_ID, requestId);
        try {
            filterChain.doFilter(request, response);
            failed = false;
        } finally {
            try {
                // Do not report an async handoff as a completed response.
                if (!request.isAsyncStarted()) {
                    logCompletion(request, response, failed, System.nanoTime() - started);
                }
            } finally {
                TrustedRequestContext.restoreMdc(TrustedRequestContext.USER_ID, previousUser);
                TrustedRequestContext.restoreMdc(TrustedRequestContext.TENANT_ID, previousTenant);
                if (previous == null) {
                    MDC.remove(REQUEST_ID);
                } else {
                    MDC.put(REQUEST_ID, previous);
                }
            }
        }
    }

    private static String requestId(HttpServletRequest request) {
        java.util.Enumeration<String> headers = request.getHeaders("X-Request-Id");
        if (headers != null && headers.hasMoreElements()) {
            String supplied = headers.nextElement();
            if (!headers.hasMoreElements() && supplied != null && supplied.length() == 36) {
                try {
                    UUID parsed = UUID.fromString(supplied);
                    if (parsed.toString().equals(supplied)) return supplied;
                } catch (IllegalArgumentException invalid) {
                    // Caller correlation values are optional; invalid values get a safe fallback.
                }
            }
        }
        return UUID.randomUUID().toString();
    }

    private static void logCompletion(HttpServletRequest request, HttpServletResponse response,
                                      boolean failed, long duration) {
        int status = failed ? 500 : response.getStatus();
        org.slf4j.spi.LoggingEventBuilder event = LOG.atInfo()
                .addKeyValue("event.action", "http.request.completed")
                .addKeyValue("event.category", List.of("web"))
                .addKeyValue("event.type", List.of("access"))
                .addKeyValue("event.outcome", status < 400 ? "success" : "failure")
                .addKeyValue("http.request.method", METHODS.contains(request.getMethod()) ? request.getMethod() : "OTHER")
                .addKeyValue("http.response.status_code", status)
                .addKeyValue("event.duration", duration);
        // Only framework-owned route templates: never raw paths, queries, headers or bodies.
        Object pattern = request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
        if (pattern instanceof String route && route.length() <= 256) {
            event.addKeyValue("url.path", route);
        }
        UUID principal = TrustedRequestContext.principal(request);
        UUID organization = TrustedRequestContext.organization(request);
        if (principal != null) event.addKeyValue(TrustedRequestContext.USER_ID, principal.toString());
        if (principal != null && organization != null) event.addKeyValue(TrustedRequestContext.TENANT_ID, organization.toString());
        event.log("HTTP request completed");
    }
}
