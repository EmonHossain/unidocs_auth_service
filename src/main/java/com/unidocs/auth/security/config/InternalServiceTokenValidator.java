package com.unidocs.auth.security.config;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public final class InternalServiceTokenValidator implements OAuth2TokenValidator<Jwt> {
    public static final String REQUIRED_SCOPE = "iam.authorization.read";
    private final InternalAuthorizationProperties properties;
    private final Clock clock;

    public InternalServiceTokenValidator(InternalAuthorizationProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        try {
            Instant now = clock.instant();
            Instant issued = jwt.getIssuedAt();
            Instant expires = jwt.getExpiresAt();
            if (!properties.enabled() || !properties.issuer().equals(jwt.getClaimAsString("iss"))
                    || !jwt.getAudience().contains(properties.audience())
                    || !properties.serviceSubjects().contains(jwt.getSubject()) || jwt.hasClaim("sid")
                    || issued == null || expires == null || issued.isAfter(now) || !expires.isAfter(now)
                    || !expires.isAfter(issued) || expires.isAfter(issued.plus(Duration.ofMinutes(5)))
                    || (jwt.getNotBefore() != null && jwt.getNotBefore().isAfter(now))) {
                throw new IllegalArgumentException();
            }
            return OAuth2TokenValidatorResult.success();
        } catch (RuntimeException exception) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid service token.", null));
        }
    }
}
