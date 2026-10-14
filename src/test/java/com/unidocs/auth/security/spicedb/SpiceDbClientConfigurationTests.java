package com.unidocs.auth.security.spicedb;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;

class SpiceDbClientConfigurationTests {
    @Test
    void plaintextTransportIsRejectedInProductionProfile() {
        Environment environment = mock(Environment.class);
        when(environment.matchesProfiles("prod")).thenReturn(true);
        SpiceDbProperties properties = new SpiceDbProperties(true, "spicedb:50051", "local-test-key", true, 500);

        assertThrows(IllegalStateException.class,
                () -> new SpiceDbClientConfiguration().spiceDbChannel(properties, environment));
    }
}
