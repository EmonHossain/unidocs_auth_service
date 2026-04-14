package com.unidocs.auth.security.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Component
public class AccessTokens {
    public static final Duration LIFETIME = Duration.ofMinutes(5);
    private final JwtKeyRing keys;
    private final Clock clock;
    private final String issuer;
    private final String audience;

    public AccessTokens(JwtKeyRing keys, Clock clock, @Value("${auth.jwt.issuer}") String issuer,
            @Value("${auth.jwt.audience}") String audience) {
        if (issuer.isBlank() || audience.isBlank()) throw new IllegalArgumentException("JWT issuer and audience are required.");
        this.keys = keys; this.clock = clock; this.issuer = issuer; this.audience = audience;
    }

    public String issue(UUID accountId, UUID sessionId) {
        Instant now = clock.instant();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject(accountId.toString()).claim("sid", sessionId.toString())
                .issuer(issuer).audience(List.of(audience)).issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(LIFETIME))).build();
        SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keys.signingKey().getKeyID())
                .type(JOSEObjectType.JWT).build(), claims);
        try {
            token.sign(new RSASSASigner(keys.signingKey()));
            return token.serialize();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Access token signing failed.");
        }
    }
}
