package com.unidocs.auth.authentication.browser;

import java.net.URI;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("auth.browser-refresh")
public record BrowserRefreshProperties(List<String> allowedOrigins) {
    public BrowserRefreshProperties {
        if (allowedOrigins != null && allowedOrigins.stream().anyMatch(java.util.Objects::isNull)) {
            throw new IllegalArgumentException("Invalid browser refresh origin configuration.");
        }
        allowedOrigins = allowedOrigins == null ? List.of() : List.copyOf(allowedOrigins);
        for (String origin : allowedOrigins) {
            try {
                URI uri = URI.create(origin);
                if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                        || uri.getRawQuery() != null || uri.getRawFragment() != null || !uri.getRawPath().isEmpty()
                        || uri.getPort() == 0 || uri.getPort() > 65535 || origin.contains("*")) {
                    throw new IllegalArgumentException();
                }
            } catch (RuntimeException invalid) {
                throw new IllegalArgumentException("Invalid browser refresh origin configuration.");
            }
        }
    }
}
