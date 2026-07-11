package com.unidocs.auth;

import com.github.benmanes.caffeine.cache.Cache;
import com.unidocs.auth.shared.config.KafkaHealthIndicator;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@SpringBootTest(properties = "AUTH_INFRASTRUCTURE_ENABLED=true")
class InfrastructureIntegrationTests extends RedisKafkaIntegrationTest {

    @Autowired StringRedisTemplate redis;
    @Autowired KafkaTemplate<String, String> kafka;
    @Autowired CacheManager caches;
    @Autowired KafkaHealthIndicator kafkaHealth;

    @Test
    void redisRoundTripSupportsExpiringDisposableEntries() {
        String key = "iam:infrastructure-test:" + UUID.randomUUID();
        redis.opsForValue().set(key, "test-projection", Duration.ofSeconds(2));
        assertThat(redis.opsForValue().get(key)).isEqualTo("test-projection");
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(redis.hasKey(key)).isFalse());
    }

    @Test
    void caffeineUsesBoundedExpiringLocalStorageAndExplicitEviction() {
        assertThat(caches).isInstanceOf(CaffeineCacheManager.class);
        CaffeineCache cache = (CaffeineCache) caches.getCache("infrastructure-test");
        assertThat(cache).isNotNull();
        Cache<Object, Object> nativeCache = cache.getNativeCache();
        assertThat(nativeCache.policy().eviction().orElseThrow().getMaximum()).isEqualTo(10000);
        assertThat(nativeCache.policy().expireAfterWrite().orElseThrow().getExpiresAfter()).isEqualTo(Duration.ofSeconds(30));
        assertThat(nativeCache.estimatedSize()).isZero();
        cache.put("test-key", "test-projection");
        assertThat(cache.get("test-key", String.class)).isEqualTo("test-projection");
        cache.evict("test-key");
        assertThat(cache.get("test-key")).isNull();
    }

    @Test
    void configuredKafkaProducerDeliversToRealBroker() throws Exception {
        String topic = "iam-infrastructure-test-" + UUID.randomUUID();
        try (AdminClient admin = AdminClient.create(Map.of("bootstrap.servers", KAFKA.getBootstrapServers()))) {
            admin.createTopics(List.of(new NewTopic(topic, 1, (short) 1))).all().get(10, TimeUnit.SECONDS);
            try {
                kafka.send(topic, "aggregate-id", "test-event").get(10, TimeUnit.SECONDS);
                Map<String, Object> properties = Map.of(
                        ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers(),
                        ConsumerConfig.GROUP_ID_CONFIG, "test-" + UUID.randomUUID(),
                        ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest",
                        ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
                try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(properties, new StringDeserializer(), new StringDeserializer())) {
                    consumer.subscribe(List.of(topic));
                    await().atMost(Duration.ofSeconds(20)).untilAsserted(() -> {
                        ConsumerRecords<String, String> records = consumer.poll(Duration.ofSeconds(1));
                        assertThat(records).anySatisfy(record -> {
                            assertThat(record.key()).isEqualTo("aggregate-id");
                            assertThat(record.value()).isEqualTo("test-event");
                        });
                    });
                }
                assertThat(kafkaHealth.health().getStatus()).isEqualTo(Status.UP);
            } finally {
                admin.deleteTopics(List.of(topic)).all().get(10, TimeUnit.SECONDS);
            }
        }
    }
}
