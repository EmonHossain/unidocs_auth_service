package com.unidocs.auth.authentication.browser;

import com.unidocs.auth.shared.config.ApiVersionProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.cors.CorsConfigurationSource;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class BrowserRefreshConfigurationTests {
    @Test
    void credentialedCorsTracksConfiguredPrefixOnly() {
        CorsConfigurationSource source = new BrowserRefreshConfiguration().corsConfigurationSource(
                new BrowserRefreshProperties(List.of("https://client.example")),
                new ApiVersionProperties("/services/auth/v2"));
        assertThat(source.getCorsConfiguration(new MockHttpServletRequest("OPTIONS", "/services/auth/v2/auth/login")))
                .satisfies(cors -> {
                    assertThat(cors.getAllowCredentials()).isTrue();
                    assertThat(cors.getAllowedOrigins()).containsExactly("https://client.example");
                });
        for (String path : List.of("/api/v1/auth/login", "/services/auth/v20/auth/login", "/services/auth/v2/me")) {
            assertThat(source.getCorsConfiguration(new MockHttpServletRequest("OPTIONS", path))).isNull();
        }
    }
}
