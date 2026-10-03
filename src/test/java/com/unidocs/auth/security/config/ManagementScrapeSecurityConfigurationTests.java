package com.unidocs.auth.security.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ManagementScrapeSecurityConfigurationTests {
    @Test
    void acceptsSeparateLoopbackListener() {
        assertThatCode(() -> ManagementScrapeSecurityConfiguration.validateListener(environment()))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {"0.0.0.0", "::", "192.168.1.10", ""})
    void rejectsNonLoopbackBindings(String address) {
        assertThatThrownBy(() -> ManagementScrapeSecurityConfiguration.validateListener(
                environment().withProperty("management.server.address", address)))
                .isInstanceOf(IllegalStateException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "-1", "8080", "65536"})
    void rejectsMissingSeparatePort(String port) {
        assertThatThrownBy(() -> ManagementScrapeSecurityConfiguration.validateListener(
                environment().withProperty("management.server.port", port)))
                .isInstanceOf(IllegalStateException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "test"})
    void acceptsExplicitPrivateListenerOnlyWithStrongTokenInDevelopment(String profile) {
        MockEnvironment environment = privateEnvironment(profile);
        assertThatCode(() -> ManagementScrapeSecurityConfiguration.validateListener(environment,
                new ManagementScrapeProperties(true, "a".repeat(32), true))).doesNotThrowAnyException();
    }

    @Test
    void developmentWithoutExplicitPermissionCannotExposeManagement() {
        assertThatThrownBy(() -> ManagementScrapeSecurityConfiguration.validateListener(privateEnvironment("dev"),
                new ManagementScrapeProperties(true, "a".repeat(32))))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void productionCannotUseDevelopmentPermissionEvenWithMixedProfiles() {
        assertThatThrownBy(() -> ManagementScrapeSecurityConfiguration.validateListener(privateEnvironment("prod", "dev"),
                new ManagementScrapeProperties(true, "a".repeat(32), true)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void explicitPermissionRequiresDevelopmentProfileAndSeparatePort() {
        assertThatThrownBy(() -> ManagementScrapeSecurityConfiguration.validateListener(privateEnvironment(),
                new ManagementScrapeProperties(true, "a".repeat(32), true)))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> ManagementScrapeSecurityConfiguration.validateListener(
                privateEnvironment("dev").withProperty("management.server.port", "8080"),
                new ManagementScrapeProperties(true, "a".repeat(32), true)))
                .isInstanceOf(IllegalStateException.class);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"short", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+"})
    void privateListenerRequiresStrongToken(String token) {
        assertThatThrownBy(() -> ManagementScrapeSecurityConfiguration.validateListener(privateEnvironment("dev"),
                new ManagementScrapeProperties(true, token, true)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static MockEnvironment privateEnvironment(String... profiles) {
        MockEnvironment environment = environment().withProperty("management.server.address", "0.0.0.0");
        environment.setActiveProfiles(profiles);
        return environment;
    }

    private static MockEnvironment environment() {
        return new MockEnvironment().withProperty("management.server.port", "9091")
                .withProperty("management.server.address", "127.0.0.1");
    }
}
