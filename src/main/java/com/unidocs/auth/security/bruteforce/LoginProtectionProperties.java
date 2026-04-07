package com.unidocs.auth.security.bruteforce;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("auth.login-protection")
public record LoginProtectionProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("auth:login:v1") String keyPrefix,
        @DefaultValue("15m") Duration window,
        @DefaultValue("50") int ipLimit,
        @DefaultValue("10") int accountLimit,
        @DefaultValue("5") int pairLimit) {
    public LoginProtectionProperties {
        if (keyPrefix == null || !keyPrefix.matches("[A-Za-z0-9:_-]{1,100}")
                || window == null || window.compareTo(Duration.ofSeconds(1)) < 0
                || window.compareTo(Duration.ofHours(24)) > 0
                || ipLimit < 1 || ipLimit > 1000000 || accountLimit < 1 || accountLimit > 1000000
                || pairLimit < 1 || pairLimit > 1000000) {
            throw new IllegalArgumentException("Invalid login protection configuration.");
        }
    }
}
