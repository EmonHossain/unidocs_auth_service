package com.unidocs.auth.security.spicedb;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class SpiceDbPropertiesTests {
    @Test
    void disabledIntegrationDoesNotRequireRuntimeCredentials() {
        assertDoesNotThrow(() -> new SpiceDbProperties(false, "", "", false, 500));
    }

    @Test
    void enabledIntegrationRequiresAnAddressAndSecret() {
        assertThrows(IllegalArgumentException.class,
                () -> new SpiceDbProperties(true, "", "", false, 500));
        assertThrows(IllegalArgumentException.class,
                () -> new SpiceDbProperties(true, "spicedb:50051", " ", false, 500));
    }

    @Test
    void rpcDeadlineMustRemainBounded() {
        assertThrows(IllegalArgumentException.class,
                () -> new SpiceDbProperties(false, "", "", false, 0));
        assertThrows(IllegalArgumentException.class,
                () -> new SpiceDbProperties(false, "", "", false, 10_001));
    }
}
