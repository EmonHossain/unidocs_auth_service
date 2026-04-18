package com.unidocs.auth.security.jwt;

import java.io.InputStream;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.converter.RsaKeyConverters;

@Configuration(proxyBeanMethods = false)
@Profile("!test | phase1-acceptance")
public class SigningKeyConfiguration {
    @Bean
    JwtKeyRing jwtKeyRing(ResourceLoader resources,
            @Value("${auth.jwt.active-kid}") String kid,
            @Value("${auth.jwt.private-key}") String privateLocation,
            @Value("${auth.jwt.public-key}") String publicLocation,
            @Value("${auth.jwt.retained-public-keys:}") String retained) throws java.io.IOException {
        LinkedHashMap<String,RSAPublicKey> publicKeys = new LinkedHashMap<String, RSAPublicKey>();
        publicKeys.put(kid, readPublic(resources, publicLocation));
        // Comma-separated kid=resource entries contain public material only.
        if (!retained.isBlank()) {
            for (String entry : retained.split(",")) {
                String[] parts = entry.strip().split("=", 2);
                if (parts.length != 2 || publicKeys.containsKey(parts[0])) {
                    throw new IllegalArgumentException("Invalid retained key configuration.");
                }
                publicKeys.put(parts[0], readPublic(resources, parts[1]));
            }
        }
        try (InputStream input = resources.getResource(privateLocation).getInputStream()) {
            return new JwtKeyRing(kid, RsaKeyConverters.pkcs8().convert(input), publicKeys);
        }
    }

    private RSAPublicKey readPublic(ResourceLoader resources, String location) throws java.io.IOException {
        try (InputStream input = resources.getResource(location).getInputStream()) {
            return RsaKeyConverters.x509().convert(input);
        }
    }
}
