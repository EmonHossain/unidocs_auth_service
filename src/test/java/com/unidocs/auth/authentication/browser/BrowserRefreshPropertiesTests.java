package com.unidocs.auth.authentication.browser;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;

class BrowserRefreshPropertiesTests {
    @Test
    void defaultsToNoTrustedOrigins() {
        assertThat(new BrowserRefreshProperties(null).allowedOrigins()).isEmpty();
        assertThat(new BrowserRefreshProperties(List.of()).allowedOrigins()).isEmpty();
    }

    @Test
    void copiesAllowedOriginsAndExposesImmutableList() {
        List<String> origins = new ArrayList<>(List.of("https://drive.example", "https://drive.example:8443"));
        BrowserRefreshProperties properties = new BrowserRefreshProperties(origins);
        origins.clear();
        assertThat(properties.allowedOrigins()).containsExactly("https://drive.example", "https://drive.example:8443");
        assertThatThrownBy(() -> properties.allowedOrigins().add("https://evil.example"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "*", "https://*.example", "http://drive.example", "https://drive.example/",
            "https://drive.example/path", "https://user@drive.example", "https://drive.example?secret=value",
            "https://drive.example#fragment", "https://", "https://drive.example https://evil.example",
            "null", "file:///drive", "https://drive.example\n"})
    void rejectsNonExactHttpsOrigins(String origin) {
        assertThatThrownBy(() -> new BrowserRefreshProperties(List.of(origin)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNullOriginEntries() {
        List<String> origins = new ArrayList<>();
        origins.add(null);
        assertThatThrownBy(() -> new BrowserRefreshProperties(origins)).isInstanceOf(IllegalArgumentException.class);
    }
}
