package com.unidocs.auth.security.jwt;

import java.nio.file.*;
import java.nio.file.Path;
import java.security.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.DefaultResourceLoader;

import com.unidocs.auth.security.jwt.JwtKeyRing;
import com.unidocs.auth.security.jwt.SigningKeyConfiguration;

import static org.assertj.core.api.Assertions.*;

class SigningKeyConfigurationTests {
    @TempDir Path directory;

    @Test void configuredPemKeysReloadAndRetainedKeysArePublicOnly() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        KeyPair current = generator.generateKeyPair(); KeyPair old = generator.generateKeyPair();
        String privateFile = pem("private.pem", "PRIVATE KEY", current.getPrivate().getEncoded());
        String publicFile = pem("public.pem", "PUBLIC KEY", current.getPublic().getEncoded());
        String oldFile = pem("old.pem", "PUBLIC KEY", old.getPublic().getEncoded());
        SigningKeyConfiguration configuration = new SigningKeyConfiguration();
        DefaultResourceLoader resources = new DefaultResourceLoader();
        JwtKeyRing first = configuration.jwtKeyRing(resources, "current", privateFile, publicFile, "old=" + oldFile);
        JwtKeyRing restarted = configuration.jwtKeyRing(resources, "current", privateFile, publicFile, "old=" + oldFile);
        assertThat(first.jwks()).isEqualTo(restarted.jwks());
        assertThat(first.verificationKeys().getKeys()).hasSize(2).allMatch(key -> !key.isPrivate());
        assertThatThrownBy(() -> configuration.jwtKeyRing(resources, "current", privateFile, oldFile, ""))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> configuration.jwtKeyRing(resources, "current", privateFile, publicFile, "current=" + oldFile))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> configuration.jwtKeyRing(resources, "current", directory.resolve("absent.pem").toUri().toString(), publicFile, ""))
                .isInstanceOf(java.io.IOException.class);
    }

    private String pem(String name, String type, byte[] bytes) throws Exception {
        String value = "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(bytes)
                + "\n-----END " + type + "-----\n";
        Path file = directory.resolve(name);
        Files.writeString(file, value);
        return file.toUri().toString();
    }

    @Test void ordinaryTestsExcludeConfiguredKeysButAcceptanceLoadsExistingKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        String privateFile = pem("acceptance-private.pem", "PRIVATE KEY", pair.getPrivate().getEncoded());
        String publicFile = pem("acceptance-public.pem", "PUBLIC KEY", pair.getPublic().getEncoded());
        for (boolean acceptance : new boolean[]{false, true}) {
            try (org.springframework.context.annotation.AnnotationConfigApplicationContext context =
                    new org.springframework.context.annotation.AnnotationConfigApplicationContext()) {
                context.getEnvironment().setActiveProfiles(acceptance ? new String[]{"test", "phase1-acceptance"} : new String[]{"test"});
                context.getEnvironment().getPropertySources().addFirst(new org.springframework.core.env.MapPropertySource(
                        "configured-keys", java.util.Map.of("auth.jwt.active-kid", "acceptance",
                        "auth.jwt.private-key", privateFile, "auth.jwt.public-key", publicFile)));
                context.register(SigningKeyConfiguration.class);
                context.refresh();
                assertThat(context.getBeansOfType(JwtKeyRing.class)).hasSize(acceptance ? 1 : 0);
                if (acceptance) {
                    assertThat(context.getBean(JwtKeyRing.class).jwks())
                            .isEqualTo(new SigningKeyConfiguration().jwtKeyRing(new DefaultResourceLoader(),
                                    "acceptance", privateFile, publicFile, "").jwks());
                }
            }
        }
    }
}
