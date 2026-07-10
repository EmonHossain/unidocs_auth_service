package com.unidocs.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ExternalTestDatabaseConfigurationTests {
    @Test
    void absentSettingsKeepTestcontainersMode() {
        assertThat(MySqlIntegrationTest.ExternalDatabase.from(Map.of())).isNull();
    }

    @Test
    void acceptsDedicatedTestSchemaAndConnectionOptions() {
        String url = "jdbc:mysql://mysql:3306/auth_service_test?useSSL=false&allowPublicKeyRetrieval=true"
                + "&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";
        MySqlIntegrationTest.ExternalDatabase database = MySqlIntegrationTest.ExternalDatabase.from(settings(url));
        assertThat(database.url()).isEqualTo(url);
        assertThat(database.username()).isEqualTo("isolated_test_user");
        assertThat(database.password()).isEqualTo("synthetic-test-secret");
    }

    @Test
    void refusesIncompleteSettingsWithoutDisclosingValues() {
        assertThatThrownBy(() -> MySqlIntegrationTest.ExternalDatabase.from(Map.of(
                "AUTH_TEST_DB_URL", "jdbc:mysql://mysql/auth_service_test",
                "AUTH_TEST_DB_PASSWORD", "synthetic-test-secret")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining("synthetic-test-secret")
                .hasMessageNotContaining("jdbc:mysql://mysql");
        assertThatThrownBy(() -> MySqlIntegrationTest.ExternalDatabase.from(Map.of(
                "AUTH_TEST_DB_USERNAME", "isolated_test_user")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesBlankCredentials() {
        assertThatThrownBy(() -> MySqlIntegrationTest.ExternalDatabase.from(Map.of(
                "AUTH_TEST_DB_URL", "jdbc:mysql://mysql/auth_service_test",
                "AUTH_TEST_DB_USERNAME", "isolated_test_user", "AUTH_TEST_DB_PASSWORD", " ")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "jdbc:mysql://mysql/auth_service", "jdbc:mysql://mysql/auth_service_test_other",
            "jdbc:mysql://mysql/", "jdbc:mysql://mysql/auth_service_test/",
            "jdbc:mysql://mysql/auth_service_test%2Fauth_service",
            "jdbc:mysql://user:secret@mysql/auth_service_test",
            "jdbc:mysql://mysql/auth_service_test#auth_service",
            "jdbc:mysql://mysql:0/auth_service_test", "jdbc:mysql://mysql:65536/auth_service_test",
            "jdbc:mysql://mysql:3306,other:3306/auth_service_test",
            "jdbc:mysql:loadbalance://mysql/auth_service_test",
            "jdbc:mysql://mysql/auth_service_test?databaseName=auth_service",
            "jdbc:mysql://mysql/auth_service_test?sessionVariables=sql_mode%3DANSI",
            "jdbc:mysql://mysql/auth_service_test?useSSL=false&",
            "jdbc:mysql://mysql/auth_service_test?connectionTimeZone=UTC;DROP",
            "jdbc:mysql://mysql/auth_service_test?allowMultiQueries=true",
            "jdbc:h2:mem:auth_service_test", "jdbc:mysql://invalid host/auth_service_test"
    })
    void refusesApplicationSchemaAndUnsafeConnectionUrls(String url) {
        assertThatThrownBy(() -> MySqlIntegrationTest.ExternalDatabase.from(settings(url)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining("synthetic-test-secret");
    }

    private Map<String, String> settings(String url) {
        return Map.of("AUTH_TEST_DB_URL", url, "AUTH_TEST_DB_USERNAME", "isolated_test_user",
                "AUTH_TEST_DB_PASSWORD", "synthetic-test-secret");
    }
}
