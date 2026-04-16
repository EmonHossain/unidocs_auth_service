package com.unidocs.auth.security.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Issues short-lived control-plane tokens with a distinct audience and principal realm. */
@Component
public class DeveloperOperatorTokens {
    public static final Duration LIFETIME = Duration.ofMinutes(5);
    private final JwtKeyRing keys;
    private final Clock clock;
    private final String issuer;
    private final String audience;

    /** Configures a signing audience distinct from product access tokens.
     * @param keys signing and verification key ring
     * @param clock time source
     * @param issuer token issuer
     * @param audience dedicated operator audience
     */
    public DeveloperOperatorTokens(JwtKeyRing keys, Clock clock, @Value("${auth.jwt.issuer}") String issuer,
            @Value("${auth.developer.jwt.audience:urn:unidocs:developer}") String audience) {
        this.keys = keys; this.clock = clock; this.issuer = issuer; this.audience = audience;
        if (audience.isBlank()) throw new IllegalArgumentException("Developer audience required.");
    }

    /** Signs an operator session token that has no product-account claims.
     * @param operatorId operator principal
     * @param sessionId current operator session
     * @return short-lived signed operator token
     */
    public String issue(UUID operatorId, UUID sessionId) {
        Instant now = clock.instant();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject(operatorId.toString())
                .claim("sid", sessionId.toString()).claim("realm", "DEVELOPER_OPERATOR")
                .issuer(issuer).audience(List.of(audience)).issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(LIFETIME))).build();
        SignedJWT token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(keys.signingKey().getKeyID()).type(JOSEObjectType.JWT).build(), claims);
        try { token.sign(new RSASSASigner(keys.signingKey())); return token.serialize(); }
        catch (JOSEException failure) { throw new IllegalStateException("Developer token signing failed."); }
    }
}
