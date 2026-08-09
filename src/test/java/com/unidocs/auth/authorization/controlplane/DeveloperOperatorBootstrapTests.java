package com.unidocs.auth.authorization.controlplane;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class DeveloperOperatorBootstrapTests {
    @Test void installationProofIsHashedBeforePersistence() throws Exception {
        Path file = Files.createTempFile("developer-activation-test", ".txt");
        try {
            String proof = "a".repeat(64);
            Files.writeString(file, proof);
            assertThat(DeveloperOperatorBootstrap.activationHash(file)).isEqualTo(DeveloperGate.hash(proof));
            assertThat(DeveloperOperatorBootstrap.activationHash(file)).doesNotContain(proof);
        } finally {
            Files.deleteIfExists(file);
        }
    }

    @Test void invalidOrMissingInstallationProofNeverActivatesSetup() throws Exception {
        Path file = Files.createTempFile("developer-activation-test", ".txt");
        try {
            Files.writeString(file, "admin");
            assertThatThrownBy(() -> DeveloperOperatorBootstrap.activationHash(file))
                    .isInstanceOf(IllegalStateException.class);
        } finally {
            Files.deleteIfExists(file);
        }
        assertThat(DeveloperOperatorBootstrap.activationHash(file)).isNull();
    }
}
