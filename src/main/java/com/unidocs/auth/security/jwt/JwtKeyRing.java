package com.unidocs.auth.security.jwt;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

public final class JwtKeyRing {
    private final RSAKey signingKey;
    private final JWKSet verificationKeys;

    public JwtKeyRing(String activeKid, RSAPrivateKey privateKey, Map<String, RSAPublicKey> publicKeys) {
        RSAPublicKey active = publicKeys.get(activeKid);
        if (activeKid == null || activeKid.isBlank() || active == null
                || !active.getModulus().equals(privateKey.getModulus())
                || (privateKey instanceof java.security.interfaces.RSAPrivateCrtKey crt
                    && !active.getPublicExponent().equals(crt.getPublicExponent()))) {
            throw new IllegalArgumentException("Signing key configuration is invalid.");
        }
        List<com.nimbusds.jose.jwk.JWK> keys = publicKeys.entrySet().stream().map(entry -> {
            if (entry.getKey().isBlank() || entry.getValue().getModulus().bitLength() < 2048) {
                throw new IllegalArgumentException("RSA verification keys require an identifier and at least 2048 bits.");
            }
            return (com.nimbusds.jose.jwk.JWK) new RSAKey.Builder(entry.getValue()).keyID(entry.getKey())
                    .keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build();
        }).toList();
        verificationKeys = new JWKSet(keys);
        signingKey = new RSAKey.Builder(active).privateKey(privateKey).keyID(activeKid)
                .keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build();
    }

    RSAKey signingKey() { return signingKey; }
    JWKSet verificationKeys() { return verificationKeys; }
    public Map<String, Object> jwks() { return verificationKeys.toJSONObject(true); }
}
