package com.unidocs.auth;

import java.util.Map;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.TestcontainersConfiguration;

/** Redis-only infrastructure avoids starting an unrelated Kafka broker. */
public abstract class RedisIntegrationTest extends MySqlIntegrationTest {
    private static final ExternalRedis EXTERNAL_REDIS = ExternalRedis.from(System.getenv());
    protected static final GenericContainer<?> REDIS = EXTERNAL_REDIS == null ? startRedis() : null;

    @DynamicPropertySource
    static void redisProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", () -> EXTERNAL_REDIS == null ? REDIS.getHost() : EXTERNAL_REDIS.host());
        registry.add("spring.data.redis.port", () -> EXTERNAL_REDIS == null ? REDIS.getMappedPort(6379) : EXTERNAL_REDIS.port());
        registry.add("spring.data.redis.database", () -> 15);
    }

    private static GenericContainer<?> startRedis() {
        GenericContainer<?> container = new GenericContainer<>(DockerImageName.parse("redis:8.2.10-alpine"))
                .withExposedPorts(6379)
                .withLabel("com.docker.compose.project", "unidocs-auth")
                .withLabel("com.docker.compose.service", "auth-test-redis")
                .withReuse(TestcontainersConfiguration.getInstance().environmentSupportsReuse());
        container.start();
        return container;
    }

    static record ExternalRedis(String host, int port) {
        static ExternalRedis from(Map<String, String> environment) {
            String host = environment.get("AUTH_TEST_REDIS_HOST");
            String port = environment.get("AUTH_TEST_REDIS_PORT");
            if (host == null && port == null) return null;
            if (host == null || !host.matches("[A-Za-z0-9_.:-]+") || port == null || !port.matches("[0-9]{1,5}")) {
                throw invalid();
            }
            int number = Integer.parseInt(port);
            if (number < 1 || number > 65535) throw invalid();
            return new ExternalRedis(host, number);
        }
        private static IllegalArgumentException invalid() {
            return new IllegalArgumentException("External Redis tests require a valid AUTH_TEST_REDIS_HOST and AUTH_TEST_REDIS_PORT");
        }
    }
}
