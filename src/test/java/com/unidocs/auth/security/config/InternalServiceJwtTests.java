package com.unidocs.auth.security.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Set;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InternalServiceJwtTests {
    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");
    private static KeyPair trusted;
    private static KeyPair attacker;
    private static NimbusJwtDecoder decoder;
    @BeforeAll static void configure() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        trusted = generator.generateKeyPair(); attacker = generator.generateKeyPair();
        decoder = NimbusJwtDecoder.withPublicKey((RSAPublicKey) trusted.getPublic()).build();
        decoder.setJwtValidator(new InternalServiceTokenValidator(new InternalAuthorizationProperties(true,
                "https://identity.example", "iam-internal", "https://identity.example/jwks", Set.of("document-service")),
                Clock.fixed(NOW, ZoneOffset.UTC)));
    }
    @Test void validatesActualSignedServiceToken() throws Exception {
        assertThat(decoder.decode(token(trusted, JWSAlgorithm.RS256, "iam-internal")).getSubject()).isEqualTo("document-service");
    }
    @Test void rejectsWrongSignature() throws Exception {
        String token = token(attacker, JWSAlgorithm.RS256, "iam-internal");
        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
    }
    @Test void rejectsUntrustedAlgorithm() throws Exception {
        String token = token(trusted, JWSAlgorithm.RS512, "iam-internal");
        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
    }
    @Test void rejectsUserAudienceEvenWithTrustedSignature() throws Exception {
        String token = token(trusted, JWSAlgorithm.RS256, "user-api");
        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
    }
    private static String token(KeyPair key, JWSAlgorithm algorithm, String audience) throws Exception {
        SignedJWT token = new SignedJWT(new JWSHeader.Builder(algorithm).keyID("test").build(),
                new JWTClaimsSet.Builder().issuer("https://identity.example").audience(audience).subject("document-service")
                        .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(120)))
                        .claim("scope", "iam.authorization.read").build());
        token.sign(new RSASSASigner((RSAPrivateKey) key.getPrivate())); return token.serialize();
    }
}
