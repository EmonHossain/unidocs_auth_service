package com.unidocs.auth.security.jwt;

import java.security.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.*;
import java.time.*;
import java.util.*;

import org.junit.jupiter.api.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.unidocs.auth.security.jwt.JwtKeyRing;

import static org.assertj.core.api.Assertions.*;

class JwtTests {
    private static final Instant NOW = Instant.parse("2026-10-02T10:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static KeyPair oldPair;
    private static KeyPair newPair;
    private JwtKeyRing oldKeys;
    private JwtDecoder decoder;

    @BeforeAll static void generateKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        oldPair = generator.generateKeyPair(); newPair = generator.generateKeyPair();
    }

    @BeforeEach void setup() {
        oldKeys = ring("old", oldPair, Map.of("old", (RSAPublicKey) oldPair.getPublic()));
        decoder = new JwtValidationConfiguration().jwtDecoder(oldKeys, CLOCK, "urn:test:issuer", "urn:test:audience");
    }

    @Test void rotationRetainsOldPublicKeyAndNewTokensUseNewKid() throws Exception {
        String old = new AccessTokens(oldKeys, CLOCK, "urn:test:issuer", "urn:test:audience").issue(UUID.randomUUID(), UUID.randomUUID());
        JwtKeyRing rotated = ring("new", newPair, Map.of("old", (RSAPublicKey) oldPair.getPublic(), "new", (RSAPublicKey) newPair.getPublic()));
        JwtDecoder rotatedDecoder = new JwtValidationConfiguration().jwtDecoder(rotated, CLOCK, "urn:test:issuer", "urn:test:audience");
        assertThat(rotatedDecoder.decode(old).getHeaders().get("kid")).isEqualTo("old");
        String token = new AccessTokens(rotated, CLOCK, "urn:test:issuer", "urn:test:audience").issue(UUID.randomUUID(), UUID.randomUUID());
        assertThat(rotatedDecoder.decode(token).getHeaders().get("kid")).isEqualTo("new");
        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
        JWKSet jwks = com.nimbusds.jose.jwk.JWKSet.parse(rotated.jwks());
        assertThat(jwks.getKeys()).hasSize(2).allMatch(key -> !key.isPrivate());
        for (JWK key : jwks.getKeys()) {
            assertThat(key.toJSONObject()).containsOnlyKeys("kty", "e", "n", "kid", "use", "alg");
        }
        JwtKeyRing retired = ring("new", newPair, Map.of("new", (RSAPublicKey) newPair.getPublic()));
        JwtDecoder retiredDecoder = new JwtValidationConfiguration().jwtDecoder(retired, CLOCK, "urn:test:issuer", "urn:test:audience");
        assertThatThrownBy(() -> retiredDecoder.decode(old)).isInstanceOf(JwtException.class);
    }

    @Test void requiredClaimsIssuerAudienceLifetimeAndExpiryAreValidated() throws Exception {
        List<JWTClaimsSet> bad = List.of(
                claims().issuer("wrong").build(), claims().audience("wrong").build(),
                claims().subject("not-a-uuid").build(), claims().subject(null).build(),
                claims().claim("sid", null).build(), claims().claim("sid", "bad").build(),
                claims().issueTime(null).build(), claims().expirationTime(null).build(),
                claims().issueTime(Date.from(NOW.plusSeconds(1))).build(),
                claims().notBeforeTime(Date.from(NOW.plusSeconds(1))).build(),
                claims().expirationTime(Date.from(NOW)).build(),
                claims().expirationTime(Date.from(NOW.minusSeconds(1))).build(),
                claims().expirationTime(Date.from(NOW.plusSeconds(301))).build());
        for (JWTClaimsSet invalid : bad) {
            String token = sign(invalid, JWSAlgorithm.RS256, "old", oldPair);
            assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
        }
        String good = sign(claims().build(), JWSAlgorithm.RS256, "old", oldPair);
        assertThat(decoder.decode(good).getClaimAsString("iss")).isEqualTo("urn:test:issuer");
    }

    @Test void algorithmsSignaturesAndMalformedTokensFailClosed() throws Exception {
        String rs512 = sign(claims().build(), JWSAlgorithm.RS512, "old", oldPair);
        String forged = sign(claims().build(), JWSAlgorithm.RS256, "old", newPair);
        String unknownKid = sign(claims().build(), JWSAlgorithm.RS256, "unknown", oldPair);
        String missingKid = sign(claims().build(), JWSAlgorithm.RS256, null, oldPair);
        String unsecured = new PlainJWT(claims().build()).serialize();
        for (String token : List.of(rs512, forged, unknownKid, missingKid, unsecured, "bad.token", "")) {
            assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
        }
    }

    @Test void issuedTokensContainOnlyRequiredIdentityClaimsAndKeepFiveMinuteLifetime() throws Exception {
        UUID accountId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        String token = new AccessTokens(oldKeys, CLOCK, "urn:test:issuer", "urn:test:audience")
                .issue(accountId, sessionId);
        SignedJWT signed = SignedJWT.parse(token);
        assertThat(signed.getHeader().toJSONObject()).containsOnlyKeys("alg", "typ", "kid");
        assertThat(signed.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(signed.getHeader().getType()).isEqualTo(JOSEObjectType.JWT);
        assertThat(signed.getHeader().getKeyID()).isEqualTo("old");
        assertThat(signed.getJWTClaimsSet().getClaims()).containsOnlyKeys("sub", "sid", "iss", "aud", "iat", "exp");
        Jwt decoded = decoder.decode(token);
        assertThat(decoded.getSubject()).isEqualTo(accountId.toString());
        assertThat(decoded.getClaimAsString("sid")).isEqualTo(sessionId.toString());
        assertThat(decoded.getIssuedAt()).isEqualTo(NOW);
        assertThat(decoded.getExpiresAt()).isEqualTo(NOW.plusSeconds(300));
        assertThat(token.length()).isLessThan(1024);
    }

    @Test void publicRsaKeyCannotBeUsedAsHmacSecretAndOtherRsaAlgorithmsAreRejected() throws Exception {
        JWSObject confused = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("old").build(),
                new Payload(claims().build().toJSONObject()));
        confused.sign(new com.nimbusds.jose.crypto.MACSigner(oldPair.getPublic().getEncoded()));
        String rs384 = sign(claims().build(), JWSAlgorithm.RS384, "old", oldPair);
        String ps256 = sign(claims().build(), JWSAlgorithm.PS256, "old", oldPair);
        for (String token : List.of(confused.serialize(), rs384, ps256)) {
            assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
        }
    }

    @Test void malformedClaimTypesAndSignedNonJsonPayloadsAreRejected() throws Exception {
        Map<String, Object> malformed = Map.of("sub", 42, "sid", List.of(UUID.randomUUID().toString()),
                "iss", 42, "aud", List.of(42), "iat", true, "exp", "tomorrow", "nbf", "later");
        for (Map.Entry<String, Object> entry : malformed.entrySet()) {
            Map<String, Object> payload = new LinkedHashMap<String, Object>(claims().build().toJSONObject());
            payload.put(entry.getKey(), entry.getValue());
            String token = signPayload(new Payload(payload));
            assertThatThrownBy(() -> decoder.decode(token)).as("claim %s", entry.getKey())
                    .isInstanceOf(JwtException.class);
        }
        for (String payload : List.of("not-json", "{", "[]", "null")) {
            String token = signPayload(new Payload(payload));
            assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
        }
    }

    @Test void missingIssuerAndAudienceAreRejected() throws Exception {
        for (JWTClaimsSet invalid : List.of(claims().issuer(null).build(), claims().audience((String) null).build(),
                claims().audience(List.of()).build())) {
            String token = sign(invalid, JWSAlgorithm.RS256, "old", oldPair);
            assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
        }
    }

    @Test void notBeforeAtCurrentTimeAndLastUnexpiredSecondAreAccepted() throws Exception {
        String token = sign(claims().notBeforeTime(Date.from(NOW)).issueTime(Date.from(NOW.minusSeconds(299)))
                .expirationTime(Date.from(NOW.plusSeconds(1))).build(), JWSAlgorithm.RS256, "old", oldPair);
        assertThat(decoder.decode(token).getExpiresAt()).isEqualTo(NOW.plusSeconds(1));
    }

    private String signPayload(Payload payload) throws Exception {
        JWSObject signed = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("old").build(), payload);
        signed.sign(new RSASSASigner((RSAPrivateKey) oldPair.getPrivate()));
        return signed.serialize();
    }
    @Test void signingConfigurationRejectsMissingMismatchedAndWeakKeys() throws Exception {
        assertThatThrownBy(() -> ring("absent", oldPair, Map.of("old", (RSAPublicKey) oldPair.getPublic())))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ring("old", newPair, Map.of("old", (RSAPublicKey) oldPair.getPublic())))
                .isInstanceOf(IllegalArgumentException.class);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(1024);
        KeyPair weak = generator.generateKeyPair();
        assertThatThrownBy(() -> ring("weak", weak, Map.of("weak", (RSAPublicKey) weak.getPublic())))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder().subject(UUID.randomUUID().toString()).claim("sid", UUID.randomUUID().toString())
                .issuer("urn:test:issuer").audience("urn:test:audience").issueTime(Date.from(NOW))
                .expirationTime(Date.from(NOW.plusSeconds(300)));
    }
    private static JwtKeyRing ring(String kid, KeyPair pair, Map<String, RSAPublicKey> keys) {
        return new JwtKeyRing(kid, (RSAPrivateKey) pair.getPrivate(), keys);
    }
    private String sign(JWTClaimsSet claims, JWSAlgorithm algorithm, String kid, KeyPair pair) throws Exception {
        SignedJWT signed = new SignedJWT(new JWSHeader.Builder(algorithm).type(JOSEObjectType.JWT).keyID(kid).build(), claims);
        signed.sign(new RSASSASigner((RSAPrivateKey) pair.getPrivate()));
        return signed.serialize();
    }
}
