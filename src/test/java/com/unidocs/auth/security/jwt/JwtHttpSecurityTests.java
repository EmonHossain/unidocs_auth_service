package com.unidocs.auth.security.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.unidocs.auth.security.config.SecurityConfiguration;
import com.unidocs.auth.security.config.SecurityProblemWriter;
import com.unidocs.auth.shared.config.RequestCorrelationFilter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = JwtHttpSecurityTests.Probe.class,
        properties = {"auth.jwt.issuer=urn:test:issuer", "auth.jwt.audience=urn:test:audience"})
@ActiveProfiles("test")
@Import({JwtHttpSecurityTests.Probe.class, JwtHttpSecurityTests.Keys.class, SecurityConfiguration.class,
        SecurityProblemWriter.class, JwtValidationConfiguration.class, RequestCorrelationFilter.class})
class JwtHttpSecurityTests {
    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final KeyPair TRUSTED = generateKey();
    private static final KeyPair ATTACKER = generateKey();
    @Autowired MockMvc mvc;
    @Autowired JwtKeyRing ring;

    @RestController
    static class Probe {
        @GetMapping("/api/v1/me")
        Map<String, String> me(@AuthenticationPrincipal Jwt jwt, org.springframework.security.core.Authentication authentication) {
            return Map.of("subject", jwt.getSubject(), "sessionId", jwt.getClaimAsString("sid"),
                    "authorities",authentication.getAuthorities().toString());
        }
    }
    @TestConfiguration(proxyBeanMethods = false)
    static class Keys {
        @Bean Clock clock() { return CLOCK; }
        @Bean JwtKeyRing jwtKeyRing() {
            return new JwtKeyRing("trusted", (RSAPrivateKey) TRUSTED.getPrivate(),
                    Map.of("trusted", (RSAPublicKey) TRUSTED.getPublic()));
        }
    }

    @Test void validBearerAuthenticatesWithoutHttpSessionOrMutableAuthorities() throws Exception {
        UUID subject = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        String token = new AccessTokens(ring, CLOCK, "urn:test:issuer", "urn:test:audience").issue(subject, session);
        MvcResult result = mvc.perform(get("/api/v1/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.subject").value(subject.toString()))
                .andExpect(jsonPath("$.sessionId").value(session.toString())).andReturn();
        assertThat(result.getRequest().getSession(false)).isNull();
        assertThat(result.getResponse().getHeader("Set-Cookie")).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"malformed", "expired", "forged", "issuer", "audience", "algorithm", "kid", "claims"})
    void invalidBearerReturnsSanitized401ThroughRealDecoder(String invalid) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().subject(UUID.randomUUID().toString())
                .claim("sid", UUID.randomUUID().toString()).issuer("urn:test:issuer").audience("urn:test:audience")
                .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(300)));
        if (invalid.equals("expired")) {
            claims.issueTime(Date.from(NOW.minusSeconds(300))).expirationTime(Date.from(NOW));
        }
        if (invalid.equals("issuer")) claims.issuer("urn:attacker:issuer");
        if (invalid.equals("audience")) claims.audience("urn:attacker:audience");
        if (invalid.equals("claims")) claims.claim("sid", null);
        JWSAlgorithm algorithm = invalid.equals("algorithm") ? JWSAlgorithm.RS512 : JWSAlgorithm.RS256;
        String kid = invalid.equals("kid") ? "attacker" : "trusted";
        SignedJWT signed = new SignedJWT(new JWSHeader.Builder(algorithm).type(JOSEObjectType.JWT).keyID(kid).build(), claims.build());
        signed.sign(new RSASSASigner((RSAPrivateKey) (invalid.equals("forged") ? ATTACKER : TRUSTED).getPrivate()));
        String token = invalid.equals("malformed") ? "attacker.invalid.token" : signed.serialize();
        MvcResult result = mvc.perform(get("/api/v1/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.requestId").exists())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(header().doesNotExist("WWW-Authenticate")).andReturn();
        assertThat(result.getResponse().getContentAsString()).doesNotContain(token, "attacker", "exception", "stackTrace");
        assertThat(result.getRequest().getSession(false)).isNull();
    }

    @Test void missingBearerIs401AndValidBearerDoesNotAuthorizeUnlistedRoute() throws Exception {
        mvc.perform(get("/api/v1/me")).andExpect(status().isUnauthorized());
        String token = new AccessTokens(ring, CLOCK, "urn:test:issuer", "urn:test:audience").issue(UUID.randomUUID(), UUID.randomUUID());
        mvc.perform(get("/api/v1/not-authorized").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.status").value(403));
    }

    @Test void signedRoleClaimsAndClientIdentityHeadersCannotSupplyAuthorities() throws Exception {
        UUID subject=UUID.randomUUID();
        UUID session=UUID.randomUUID();
        JWTClaimsSet claims=new JWTClaimsSet.Builder().subject(subject.toString()).claim("sid",session.toString())
                .issuer("urn:test:issuer").audience("urn:test:audience")
                .issueTime(Date.from(NOW)).expirationTime(Date.from(NOW.plusSeconds(300)))
                .claim("role","ADMIN").claim("roles",java.util.List.of("OWNER","ADMIN"))
                .claim("authorities",java.util.List.of("ROLE_ADMIN"))
                .claim("scope","ADMIN write:all").claim("scp",java.util.List.of("ADMIN")).build();
        SignedJWT signed=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT).keyID("trusted").build(),claims);
        signed.sign(new RSASSASigner((RSAPrivateKey)TRUSTED.getPrivate()));
        mvc.perform(get("/api/v1/me").header("Authorization","Bearer "+signed.serialize())
                .header("X-User-Id",UUID.randomUUID().toString()).header("X-Roles","OWNER,ADMIN"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.subject").value(subject.toString()))
                .andExpect(jsonPath("$.authorities").value("[]"));
        mvc.perform(get("/api/v1/admin/probe").header("Authorization","Bearer "+signed.serialize()))
                .andExpect(status().isForbidden());
    }

    private static KeyPair generateKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (java.security.GeneralSecurityException unavailable) {
            throw new IllegalStateException("Test RSA key generation failed.");
        }
    }
}
