package com.unidocs.auth.shared.config;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxy;
import org.junit.jupiter.api.Test;
import org.slf4j.event.KeyValuePair;
import org.springframework.boot.logging.logback.StructuredLogEncoder;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.mock.env.MockEnvironment;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class ObservabilityLoggingTests {
    private static final String REQUEST_ID = "a5b3b0cc-7d92-4e5b-b26d-87a8e0cdd63f";

    @Test
    void configuredEcsOutputContainsServiceMetadataAndSafeAuthenticationFields() throws Exception {
        LoggingEvent event = event("Authentication attempt completed", Map.of("requestId", REQUEST_ID));
        event.addKeyValuePair(new KeyValuePair("event.action", "auth.login.failed"));
        event.addKeyValuePair(new KeyValuePair("event.category", List.of("authentication")));
        event.addKeyValuePair(new KeyValuePair("event.outcome", "failure"));


        String output = encode(event);
        JsonNode json = JsonMapper.builder().build().readTree(output);

        assertThat(Instant.parse(json.path("@timestamp").asText())).isEqualTo(Instant.parse("2026-10-08T10:15:30Z"));
        assertThat(json.at("/ecs/version").asText()).isNotBlank();
        assertThat(json.at("/log/level").asText()).isEqualTo("INFO");
        assertThat(json.at("/log/logger").asText()).isEqualTo("com.unidocs.auth.authentication.application.AuthenticationService");
        assertThat(json.path("message").asText()).isEqualTo("Authentication attempt completed");
        assertThat(json.at("/service/name").asText()).isEqualTo("auth-service");
        assertThat(json.at("/service/version").asText()).isEqualTo("0.0.1-SNAPSHOT");
        assertThat(json.at("/service/environment").asText()).isEqualTo("dev");
        assertThat(json.at("/event/action").asText()).isEqualTo("auth.login.failed");
        assertThat(json.at("/event/category").get(0).asText()).isEqualTo("authentication");
        assertThat(json.at("/event/outcome").asText()).isEqualTo("failure");
        assertThat(json.path("http.request.id").asText()).isEqualTo(REQUEST_ID);
        assertThat(json.has("requestId")).isFalse();
        assertThat(json.has("user.id")).isFalse();
        assertThat(json.has("labels.tenant_id")).isFalse();
        assertThat(output.lines().count()).isEqualTo(1);
    }

    @Test
    void escapesNewlinesAndQuotesWithoutCreatingAdditionalLogRecords() throws Exception {
        String message = "Safe summary\n\"event.action\":\"forged\"\r\n";
        String output = encode(event(message));

        assertThat(output.lines().count()).isEqualTo(1);
        assertThat(JsonMapper.builder().build().readTree(output).path("message").asText()).isEqualTo(message);
        assertThat(output).contains("\\n", "\\r", "\\\"");
    }

    @Test
    void omitsSecretBearingExceptionMessageAndStackTrace() throws Exception {
        LoggingEvent event = event("Authentication attempt failed");
        event.setThrowableProxy(new ThrowableProxy(new IllegalArgumentException(
                "password=secret-password Bearer secret-jwt refresh_token=secret-refresh otp=123456 Cookie=secret-cookie")));
        String output = encode(event);
        JsonNode json = JsonMapper.builder().build().readTree(output);

        assertThat(output).doesNotContain("secret-password", "secret-jwt", "secret-refresh", "123456", "secret-cookie");
        assertThat(!json.at("/error/message").isMissingNode()).isFalse();
        assertThat(!json.at("/error/stack_trace").isMissingNode()).isFalse();
        assertThat(json.at("/error/type").asText()).isEqualTo(IllegalArgumentException.class.getName());
    }

    @Test
    void productionFileOutputPreservesSafeStructuredLogsWithoutConsoleOrSwagger() throws Exception {
        Properties properties = PropertiesLoaderUtils.loadProperties(new ClassPathResource("application-prod.properties"));
        assertThat(properties.getProperty("logging.console.enabled")).isEqualTo("false");
        assertThat(properties.getProperty("logging.file.name")).isEqualTo("/var/log/unidocs/auth-service.log");
        assertThat(properties.getProperty("springdoc.api-docs.enabled")).isEqualTo("false");
        assertThat(properties.getProperty("springdoc.swagger-ui.enabled")).isEqualTo("false");
        assertThat(properties.getProperty("logging.level.root")).isEqualTo("INFO");
        assertThat(properties.getProperty("logging.level.com.unidocs.auth")).isEqualTo("INFO");
        assertThat(properties.getProperty("server.ssl.enabled")).isEqualTo("true");
        assertThat(properties.getProperty("server.ssl.key-store")).isEqualTo("file:/run/secrets/application/auth-local-tls.p12");
        assertThat(properties.getProperty("server.ssl.key-store-password")).isEqualTo("${AUTH_TLS_STORE_PASSWORD}");
        assertThat(properties.getProperty("management.server.ssl.enabled")).isEqualTo("false");
        LoggingEvent event = event("Authentication attempt failed", Map.of("requestId", REQUEST_ID));
        event.setThrowableProxy(new ThrowableProxy(new IllegalArgumentException("password=production-secret")));
        String output = encode(event, "prod", "file");
        JsonNode json = JsonMapper.builder().build().readTree(output);
        assertThat(json.at("/service/environment").asText()).isEqualTo("prod");
        assertThat(json.path("http.request.id").asText()).isEqualTo(REQUEST_ID);
        assertThat(json.at("/ecs/version").asText()).isNotBlank();
        assertThat(output).doesNotContain("production-secret");
        assertThat(output.lines().count()).isEqualTo(1);
    }

    private LoggingEvent event(String message) {
        return event(message, Map.of());
    }

    private LoggingEvent event(String message, Map<String, String> mdc) {
        LoggingEvent event = new LoggingEvent();
        event.setLevel(Level.INFO);
        event.setLoggerName("com.unidocs.auth.authentication.application.AuthenticationService");
        event.setMessage(message);
        event.setThreadName("observability-contract-test");
        event.setInstant(Instant.parse("2026-10-08T10:15:30Z"));
        event.setMDCPropertyMap(mdc);
        return event;
    }

    private String encode(LoggingEvent event) throws Exception {
        return encode(event, null, "console");
    }

    private String encode(LoggingEvent event, String profile, String destination) throws Exception {
        Properties properties = PropertiesLoaderUtils.loadProperties(new ClassPathResource("application.properties"));
        MockEnvironment environment = new MockEnvironment();
        if (profile != null) {
            Properties overrides = PropertiesLoaderUtils.loadProperties(new ClassPathResource("application-" + profile + ".properties"));
            environment.getPropertySources().addFirst(new PropertiesPropertySource("profile", overrides));
        }
        environment.getPropertySources().addLast(new PropertiesPropertySource("application", properties));
        LoggerContext context = new LoggerContext();
        context.putObject(Environment.class.getName(), environment);
        StructuredLogEncoder encoder = new StructuredLogEncoder();
        encoder.setContext(context);
        encoder.setFormat(environment.getRequiredProperty("logging.structured.format." + destination));
        try {
            encoder.start();
            return new String(encoder.encode(event), StandardCharsets.UTF_8);
        } finally {
            encoder.stop();
            context.stop();
        }
    }
}




