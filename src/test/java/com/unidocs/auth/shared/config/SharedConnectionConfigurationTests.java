package com.unidocs.auth.shared.config;

import java.io.IOException;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

class SharedConnectionConfigurationTests {
    @Test
    void sharedDatabaseConnectionKeepsPrivateDatabaseAndOptions() throws IOException {
        MockEnvironment environment = environment()
                .withProperty("SHARED_MYSQL_HOST", "shared-mysql")
                .withProperty("SHARED_MYSQL_PORT", "4406")
                .withProperty("DB_NAME", "private_auth")
                .withProperty("DB_URL_OPTIONS", "connectionTimeZone=UTC&sslMode=REQUIRED")
                .withProperty("DB_USERNAME", "private_user")
                .withProperty("DB_PASSWORD", "test-private-password");

        assertThat(environment.getRequiredProperty("spring.datasource.url"))
                .isEqualTo("jdbc:mysql://shared-mysql:4406/private_auth?connectionTimeZone=UTC&sslMode=REQUIRED");
        assertThat(environment.getRequiredProperty("spring.datasource.username")).isEqualTo("private_user");
        assertThat(environment.getRequiredProperty("spring.datasource.password")).isEqualTo("test-private-password");
    }

    @Test
    void sharedStorageAndTracingConnectionsReachRuntime() throws IOException {
        MockEnvironment environment = environment()
                .withProperty("SHARED_STORAGE_ENDPOINT", "http://shared-storage:9100")
                .withProperty("SHARED_OTLP_TRACING_ENDPOINT", "http://shared-apm:8300/v1/traces");

        assertThat(environment.getRequiredProperty("registration.student.storage.endpoint"))
                .isEqualTo("http://shared-storage:9100");
        assertThat(environment.getRequiredProperty("management.opentelemetry.tracing.export.otlp.endpoint"))
                .isEqualTo("http://shared-apm:8300/v1/traces");
    }

    @Test
    void explicitRuntimeConnectionsOverrideSharedConnections() throws IOException {
        MockEnvironment environment = environment()
                .withProperty("SHARED_MYSQL_HOST", "shared-mysql")
                .withProperty("SHARED_MYSQL_PORT", "4406")
                .withProperty("SHARED_STORAGE_ENDPOINT", "http://shared-storage:9100")
                .withProperty("SHARED_OTLP_TRACING_ENDPOINT", "http://shared-apm:8300/v1/traces")
                .withProperty("DB_URL", "jdbc:mysql://override-mysql:3306/override_auth")
                .withProperty("STUDENT_STORAGE_ENDPOINT", "http://override-storage:9000")
                .withProperty("AUTH_OTLP_TRACING_ENDPOINT", "http://override-apm:8200/v1/traces");

        assertThat(environment.getRequiredProperty("spring.datasource.url"))
                .isEqualTo("jdbc:mysql://override-mysql:3306/override_auth");
        assertThat(environment.getRequiredProperty("registration.student.storage.endpoint"))
                .isEqualTo("http://override-storage:9000");
        assertThat(environment.getRequiredProperty("management.opentelemetry.tracing.export.otlp.endpoint"))
                .isEqualTo("http://override-apm:8200/v1/traces");
    }

    @Test
    void sharedKeycloakNavigationDoesNotChangePrivateTrustOrEnableAuthorization() throws IOException {
        MockEnvironment environment = environment()
                .withProperty("SHARED_KEYCLOAK_BASE_URL", "https://shared-keycloak:9443")
                .withProperty("SHARED_KEYCLOAK_REALM", "shared-realm")
                .withProperty("INTERNAL_AUTHORIZATION_ISSUER", "https://private-issuer/realms/private-realm")
                .withProperty("INTERNAL_AUTHORIZATION_AUDIENCE", "private-audience");

        assertThat(environment.getRequiredProperty("auth.internal-authorization.issuer"))
                .isEqualTo("https://private-issuer/realms/private-realm");
        assertThat(environment.getRequiredProperty("auth.internal-authorization.audience"))
                .isEqualTo("private-audience");
        assertThat(environment.getRequiredProperty("auth.internal-authorization.enabled")).isEqualTo("false");
        assertThat(environment.getRequiredProperty("auth.internal-authorization.jwk-set-uri")).isEmpty();
    }

    @Test
    void standaloneDefaultsRemainAvailableWithoutSharedSettings() throws IOException {
        MockEnvironment environment = environment();

        assertThat(environment.getRequiredProperty("spring.datasource.url"))
                .isEqualTo("jdbc:mysql://localhost:3306/auth_service?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true");
        assertThat(environment.getRequiredProperty("registration.student.storage.endpoint"))
                .isEqualTo("http://localhost:9000");
        assertThat(environment.getRequiredProperty("management.opentelemetry.tracing.export.otlp.endpoint"))
                .isEqualTo("http://localhost:4318/v1/traces");
    }

    private MockEnvironment environment() throws IOException {
        Properties properties = PropertiesLoaderUtils.loadProperties(new ClassPathResource("application.properties"));
        MockEnvironment environment = new MockEnvironment();
        environment.getPropertySources().addLast(new PropertiesPropertySource("application", properties));
        return environment;
    }
}
