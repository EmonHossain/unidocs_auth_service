package com.unidocs.auth;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;

class ExternalRedisConfigurationTests {
    @Test void unsetUsesTestcontainers() {
        assertThat(RedisIntegrationTest.ExternalRedis.from(Map.of())).isNull();
    }
    @Test void composeSettingsUseExistingRedis() {
        RedisIntegrationTest.ExternalRedis redis = RedisIntegrationTest.ExternalRedis.from(
                Map.of("AUTH_TEST_REDIS_HOST", "redis", "AUTH_TEST_REDIS_PORT", "6379"));
        assertThat(redis.host()).isEqualTo("redis");
        assertThat(redis.port()).isEqualTo(6379);
    }
    @ParameterizedTest @ValueSource(strings={"", "0", "65536", "-1", "secret", "6379/0"})
    void invalidPortIsRejectedWithoutLeakingConfiguration(String value) {
        assertThatThrownBy(() -> RedisIntegrationTest.ExternalRedis.from(
                Map.of("AUTH_TEST_REDIS_HOST", "redis", "AUTH_TEST_REDIS_PORT", value)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("External Redis tests require a valid AUTH_TEST_REDIS_HOST and AUTH_TEST_REDIS_PORT");
    }
    @Test void incompleteSettingsAreRejected() {
        assertThatThrownBy(() -> RedisIntegrationTest.ExternalRedis.from(Map.of("AUTH_TEST_REDIS_HOST", "redis")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RedisIntegrationTest.ExternalRedis.from(Map.of("AUTH_TEST_REDIS_PORT", "6379")))
                .isInstanceOf(IllegalArgumentException.class);
    }
    @ParameterizedTest @ValueSource(strings={"", "redis://secret@host", "host/path", "host?password=secret", "host name"})
    void invalidHostIsRejected(String value) {
        assertThatThrownBy(() -> RedisIntegrationTest.ExternalRedis.from(
                Map.of("AUTH_TEST_REDIS_HOST", value, "AUTH_TEST_REDIS_PORT", "6379")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("External Redis tests require a valid AUTH_TEST_REDIS_HOST and AUTH_TEST_REDIS_PORT");
    }
}
