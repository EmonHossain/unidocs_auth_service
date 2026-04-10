package com.unidocs.auth.security.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.List;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Registered exclusively in the management scrape security chain. */
public final class ManagementScrapeAuthenticationFilter extends OncePerRequestFilter {
    private final byte[] tokenDigest;

    public ManagementScrapeAuthenticationFilter(ManagementScrapeProperties properties) {
        properties.validate();
        tokenDigest = properties.enabled() ? digest(properties.token()) : null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        SecurityContext previousContext = SecurityContextHolder.getContext();
        SecurityContext scrapeContext = SecurityContextHolder.createEmptyContext();
        if (validAuthorization(request)) {
            scrapeContext.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                    "prometheus-scraper", null, List.of(new SimpleGrantedAuthority("ROLE_METRICS_SCRAPER"))));
        }
        try {
            SecurityContextHolder.setContext(scrapeContext);
            chain.doFilter(request, response);
        } finally {
            SecurityContextHolder.setContext(previousContext);
        }
    }

    private boolean validAuthorization(HttpServletRequest request) {
        if (tokenDigest == null) return false;
        Enumeration<String> headers = request.getHeaders("Authorization");
        if (headers == null || !headers.hasMoreElements()) return false;
        String header = headers.nextElement();
        if (headers.hasMoreElements() || header == null || header.length() > 263
                || !header.startsWith("Bearer ")) return false;
        String suppliedToken = header.substring(7);
        return ManagementScrapeProperties.validToken(suppliedToken)
                && MessageDigest.isEqual(tokenDigest, digest(suppliedToken));
    }

    private static byte[] digest(String token) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("Management scrape authentication is unavailable.");
        }
    }
}
