package com.unidocs.auth.security.config;

import java.net.URI;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("auth.internal-authorization")
public record InternalAuthorizationProperties(boolean enabled, String issuer, String audience,
        String jwkSetUri, Set<String> serviceSubjects) {
    public InternalAuthorizationProperties {
        serviceSubjects = serviceSubjects == null ? Set.of() : Set.copyOf(serviceSubjects);
        if (enabled && (issuer == null || issuer.isBlank() || audience == null || audience.isBlank()
                || serviceSubjects.isEmpty() || serviceSubjects.stream().anyMatch(String::isBlank)
                || !secureUri(jwkSetUri))) {
            throw new IllegalArgumentException("Internal authorization requires trusted service identity configuration.");
        }
    }

    private static boolean secureUri(String value) {
        try {
            URI uri = URI.create(value);
            return "https".equals(uri.getScheme()) && uri.getHost() != null
                    && uri.getUserInfo() == null && uri.getFragment() == null;
        } catch (RuntimeException exception) { return false; }
    }
}
