package com.unidocs.auth;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.TestcontainersConfiguration;

public abstract class RedisKafkaIntegrationTest extends KafkaIntegrationTest {
    protected static final GenericContainer<?> REDIS = startRedis();

    private static GenericContainer<?> startRedis() {
        GenericContainer<?> container = new GenericContainer<>(DockerImageName.parse("redis:8.2.10-alpine"))
                .withExposedPorts(6379)
                .withReuse(TestcontainersConfiguration.getInstance().environmentSupportsReuse());
        container.start();
        return container;
    }

    @DynamicPropertySource
    static void redisProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
    }
}
