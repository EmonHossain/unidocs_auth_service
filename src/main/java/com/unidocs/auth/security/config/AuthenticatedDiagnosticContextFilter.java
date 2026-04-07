package com.unidocs.auth.security.config;

import java.io.IOException;
import java.util.UUID;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;
import com.unidocs.auth.shared.config.TrustedRequestContext;

/** Registered only inside the security chain, after bearer-token authentication. */
public final class AuthenticatedDiagnosticContextFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String previousUser = MDC.get(TrustedRequestContext.USER_ID);
        String previousTenant = MDC.get(TrustedRequestContext.TENANT_ID);
        try {
            MDC.remove(TrustedRequestContext.USER_ID);
            MDC.remove(TrustedRequestContext.TENANT_ID);
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication instanceof JwtAuthenticationToken jwt && jwt.isAuthenticated()) {
                UUID principal = principal(jwt.getToken().getSubject());
                if (principal != null) TrustedRequestContext.authenticatedPrincipal(request, principal);
            }
            chain.doFilter(request, response);
        } finally {
            TrustedRequestContext.restoreMdc(TrustedRequestContext.USER_ID, previousUser);
            TrustedRequestContext.restoreMdc(TrustedRequestContext.TENANT_ID, previousTenant);
        }
    }

    private static UUID principal(String subject) {
        if (subject == null || subject.length() != 36) return null;
        try {
            UUID principal = UUID.fromString(subject);
            return principal.toString().equals(subject) ? principal : null;
        } catch (IllegalArgumentException invalid) {
            return null;
        }
    }
}
