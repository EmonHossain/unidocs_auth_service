package com.unidocs.auth.security.jwt;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

@Configuration(proxyBeanMethods = false)
public class JwtValidationConfiguration {
    @Bean
    JwtDecoder jwtDecoder(JwtKeyRing keys, Clock clock, @Value("${auth.jwt.issuer}") String issuer,
            @Value("${auth.jwt.audience}") String audience) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<SecurityContext>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256,
                new ImmutableJWKSet<>(keys.verificationKeys())));
        // All claim validation uses the same injectable UTC clock as session authorization.
        processor.setJWTClaimsSetVerifier((claims, context) -> { });
        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(jwt -> {
            try {
                UUID.fromString(jwt.getSubject());
                UUID.fromString(jwt.getClaimAsString("sid"));
                Instant issued = jwt.getIssuedAt();
                Instant expires = jwt.getExpiresAt();
                Instant now = clock.instant();
                if (!(jwt.getHeaders().get("kid") instanceof String kid) || kid.isBlank()
                        || !issuer.equals(jwt.getClaimAsString("iss")) || !jwt.getAudience().contains(audience)
                        || issued == null || expires == null || issued.isAfter(now)
                        || (jwt.getNotBefore() != null && jwt.getNotBefore().isAfter(now))
                        || !expires.isAfter(now) || !expires.isAfter(issued)
                        || expires.isAfter(issued.plus(AccessTokens.LIFETIME))) throw new IllegalArgumentException();
                return OAuth2TokenValidatorResult.success();
            } catch (RuntimeException exception) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid access token.", null));
            }
        });
        return decoder;
    }
}
