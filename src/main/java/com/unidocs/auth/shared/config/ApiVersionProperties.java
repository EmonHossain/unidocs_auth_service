package com.unidocs.auth.shared.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("api.version")
public record ApiVersionProperties(String basePath) {
    public static final String DEFAULT_BASE_PATH="/api/v1";

    public ApiVersionProperties {
        if (basePath==null) basePath=DEFAULT_BASE_PATH;
        if (!basePath.matches("/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*")) {
            throw new IllegalArgumentException("API base path must be a canonical absolute path without a trailing slash.");
        }
    }

    public String path(String suffix) { return basePath+suffix; }
}
