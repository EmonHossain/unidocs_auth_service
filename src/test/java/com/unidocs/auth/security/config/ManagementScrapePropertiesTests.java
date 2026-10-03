package com.unidocs.auth.security.config;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ManagementScrapePropertiesTests {
    @Test void constructorBindingKeepsPrivateListenerDisabledUnlessExplicitlyConfigured() {
        Map<String, String> values = Map.of("auth.management.scrape.enabled", "true",
                "auth.management.scrape.token", "a".repeat(32));
        ManagementScrapeProperties defaults = new Binder(new MapConfigurationPropertySource(values))
                .bind("auth.management.scrape", Bindable.of(ManagementScrapeProperties.class)).get();
        assertThat(defaults.allowPrivateNetwork()).isFalse();
        ManagementScrapeProperties optedIn = new Binder(new MapConfigurationPropertySource(Map.of(
                "auth.management.scrape.enabled", "true", "auth.management.scrape.token", "a".repeat(32),
                "auth.management.scrape.allow-private-network", "true")))
                .bind("auth.management.scrape", Bindable.of(ManagementScrapeProperties.class)).get();
        assertThat(optedIn.allowPrivateNetwork()).isTrue();
        optedIn.validate();
    }

    @Test void disabledDoesNotRequireToken() {
        assertThat(new ManagementScrapeProperties(false, "").enabled()).isFalse();
    }

    @Test void acceptsBoundedUrlSafeTokensWithoutExposingThem() {
        String token = "aB09_-".repeat(6);
        ManagementScrapeProperties properties = new ManagementScrapeProperties(true, token);
        assertThat(properties.token()).isEqualTo(token);
        assertThat(properties.toString()).doesNotContain(token).contains("[REDACTED]");
        new ManagementScrapeProperties(true, "a".repeat(32)).validate();
        new ManagementScrapeProperties(true, "a".repeat(256)).validate();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"short", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaé", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"})
    void enabledRejectsInvalidTokensWithSanitizedErrors(String token) {
        assertThatThrownBy(() -> new ManagementScrapeProperties(true, token).validate())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Enabled management scraping requires a valid token.");
    }

    @Test void rejectsOversizedAndUndersizedTokens() {
        assertThatThrownBy(() -> new ManagementScrapeProperties(true, "a".repeat(31)).validate())
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ManagementScrapeProperties(true, "a".repeat(257)).validate())
                .isInstanceOf(IllegalArgumentException.class);
    }
}
