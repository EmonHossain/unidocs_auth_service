package com.unidocs.auth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.*;
import java.util.Map;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import com.unidocs.auth.security.jwt.JwtKeyRing;

@TestConfiguration(proxyBeanMethods = false)
public class TestSigningKeys {
    @Bean
    public JwtKeyRing testJwtKeyRing() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return new JwtKeyRing("test-key", (RSAPrivateKey) pair.getPrivate(),
                Map.of("test-key", (RSAPublicKey) pair.getPublic()));
    }
}
