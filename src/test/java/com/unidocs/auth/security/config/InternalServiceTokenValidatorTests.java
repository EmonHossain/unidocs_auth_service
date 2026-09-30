package com.unidocs.auth.security.config;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.jwt.Jwt;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InternalServiceTokenValidatorTests {
    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");
    private static final InternalAuthorizationProperties PROPERTIES = new InternalAuthorizationProperties(true,
            "https://identity.example", "iam-internal", "https://identity.example/jwks", Set.of("document-service"));
    private final InternalServiceTokenValidator validator = new InternalServiceTokenValidator(PROPERTIES,
            Clock.fixed(NOW, ZoneOffset.UTC));

    @Test void acceptsShortLivedAllowlistedService() { assertThat(validator.validate(token(builder -> {})).hasErrors()).isFalse(); }
    @Test void rejectsUserIdentity() { assertThat(validator.validate(token(builder -> builder.claim("sid", "session"))).hasErrors()).isTrue(); }
    @Test void rejectsWrongIssuer() { assertThat(validator.validate(token(builder -> builder.issuer("user-issuer"))).hasErrors()).isTrue(); }
    @Test void rejectsWrongAudience() { assertThat(validator.validate(token(builder -> builder.audience(java.util.List.of("user-api")))).hasErrors()).isTrue(); }
    @Test void rejectsUnlistedService() { assertThat(validator.validate(token(builder -> builder.subject("unknown"))).hasErrors()).isTrue(); }
    @Test void rejectsExpiredToken() { assertThat(validator.validate(token(builder -> builder.issuedAt(NOW.minusSeconds(60)).expiresAt(NOW))).hasErrors()).isTrue(); }
    @Test void rejectsExcessLifetime() { assertThat(validator.validate(token(builder -> builder.expiresAt(NOW.plusSeconds(301)))).hasErrors()).isTrue(); }
    @Test void rejectsFutureIssuedToken() { assertThat(validator.validate(token(builder -> builder.issuedAt(NOW.plusSeconds(1)))).hasErrors()).isTrue(); }
    @Test void rejectsFutureNotBefore() { assertThat(validator.validate(token(builder -> builder.notBefore(NOW.plusSeconds(1)))).hasErrors()).isTrue(); }
    @Test void defaultIsDisabled() { assertThat(new InternalAuthorizationProperties(false, null, null, null, null).enabled()).isFalse(); }
    @ParameterizedTest @ValueSource(strings = {"http://identity.example/jwks", "https://user:secret@identity.example/jwks", "invalid", ""})
    void rejectsUnsafeTrustConfiguration(String uri) {
        assertThatThrownBy(() -> new InternalAuthorizationProperties(true, "issuer", "audience", uri,
                Set.of("document-service"))).isInstanceOf(IllegalArgumentException.class);
    }
    private static Jwt token(Consumer<Jwt.Builder> mutation) {
        Jwt.Builder builder = Jwt.withTokenValue("test").header("alg", "RS256").issuer(PROPERTIES.issuer())
                .audience(java.util.List.of(PROPERTIES.audience())).subject("document-service")
                .issuedAt(NOW).expiresAt(NOW.plusSeconds(120));
        mutation.accept(builder);
        return builder.build();
    }
}

