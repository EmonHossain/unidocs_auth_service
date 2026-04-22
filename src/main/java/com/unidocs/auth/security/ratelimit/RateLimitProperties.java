package com.unidocs.auth.security.ratelimit;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
@ConfigurationProperties("auth.rate-limit")
public record RateLimitProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("auth:rate:v1") String keyPrefix,
        @DefaultValue("1m") Duration window,
        @DefaultValue("10") int registrationLimit,
        @DefaultValue("60") int loginLimit,
        @DefaultValue("120") int refreshLimit,
        @DefaultValue("10") int forgotPasswordLimit,
        @DefaultValue("20") int resetPasswordLimit,
        @DefaultValue("20") int verificationLimit) {
    public RateLimitProperties {
        if (keyPrefix == null || !keyPrefix.matches("[A-Za-z0-9:_-]{1,100}")
                || window == null || window.compareTo(Duration.ofSeconds(1)) < 0
                || window.compareTo(Duration.ofHours(24)) > 0) {
            throw new IllegalArgumentException("Invalid rate limit configuration.");
        }
        for (int limit : new int[]{registrationLimit, loginLimit, refreshLimit,
                forgotPasswordLimit, resetPasswordLimit, verificationLimit}) {
            if (limit < 1 || limit > 1000000) throw new IllegalArgumentException("Invalid rate limit configuration.");
        }
    }
    public int limit(RateLimitPolicy policy) {
        return switch (policy) {
            case REGISTRATION -> registrationLimit;
            case LOGIN -> loginLimit;
            case REFRESH -> refreshLimit;
            case FORGOT_PASSWORD -> forgotPasswordLimit;
            case RESET_PASSWORD -> resetPasswordLimit;
            case VERIFICATION -> verificationLimit;
        };
    }
}
