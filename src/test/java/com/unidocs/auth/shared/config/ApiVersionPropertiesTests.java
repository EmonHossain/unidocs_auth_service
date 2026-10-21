package com.unidocs.auth.shared.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;

class ApiVersionPropertiesTests {
    @Test void defaultAndCustomPrefixesBuildRoutes() {
        assertThat(new ApiVersionProperties(null).path("/auth/login")).isEqualTo("/api/v1/auth/login");
        assertThat(new ApiVersionProperties("/gateway/api/v7").path("/auth/login")).isEqualTo("/gateway/api/v7/auth/login");
    }

    @ParameterizedTest
    @ValueSource(strings={"", "api/v1", "/", "/api/v1/", "/api//v1", "/api/*", "/api/{version}",
            "/api/../v1", "/api/v1?x=1", "https://example.com/api/v1"})
    void malformedOrAmbiguousPrefixesAreRejected(String path) {
        assertThatIllegalArgumentException().isThrownBy(()->new ApiVersionProperties(path));
    }
}
