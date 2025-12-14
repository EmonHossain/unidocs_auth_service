package com.unidocs.auth.authorization.application;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.unidocs.auth.authorization.domain.OperationPolicyCandidate;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.json.JsonMapper;

@Component
public class OperationPolicyCandidateCache {
    private final Cache<String, OperationPolicyCandidate> local = Caffeine.newBuilder().maximumSize(1000)
            .expireAfterWrite(Duration.ofSeconds(60)).build();
    private final AtomicLong floor = new AtomicLong(1);
    private final StringRedisTemplate redis;
    private final JsonMapper json;
    private final MeterRegistry metrics;
    private final boolean enabled;
    private static final DefaultRedisScript<Long> WRITE = new DefaultRedisScript<>("""
            local previous = redis.call('GET', KEYS[2])
            local proposed = ARGV[1]
            if previous and (#previous > #proposed or (#previous == #proposed and previous > proposed)) then return 0 end
            redis.call('SET', KEYS[1], ARGV[2], 'EX', 60)
            redis.call('SET', KEYS[2], proposed, 'EX', 60)
            return 1
            """, Long.class);

    public OperationPolicyCandidateCache(StringRedisTemplate redis, JsonMapper json, MeterRegistry metrics,
            @Value("${auth.authorization.cache.enabled:false}") boolean enabled) {
        this.redis = redis; this.json = json; this.metrics = metrics; this.enabled = enabled;
    }

    public Optional<OperationPolicyCandidate> find(String operationKey) {
        outsideTransaction();
        if (!enabled) return Optional.empty();
        OperationPolicyCandidate candidate = local.get(operationKey, key -> {
            try {
                String raw = redis.opsForValue().get(redisKey(key));
                if (raw != null && raw.length() <= 32768) {
                    OperationPolicyCandidate shared = json.readValue(raw, OperationPolicyCandidate.class);
                    if (usable(key, shared)) return shared;
                }
            } catch (RuntimeException unavailable) { outcome("redis_unavailable"); }
            return null;
        });
        if (!usable(operationKey, candidate)) { local.invalidate(operationKey); outcome("miss"); return Optional.empty(); }
        outcome("payload_hit");
        return Optional.of(candidate);
    }

    public void put(OperationPolicyCandidate candidate) {
        outsideTransaction();
        if (!enabled) return;
        String key = candidate.snapshot().operationKey();
        if (!usable(key, candidate)) return;
        local.asMap().compute(key, (ignored, previous) -> previous != null && previous.catalogVersion() > candidate.catalogVersion() ? previous : candidate);
        // Recheck the floor after filling to reject invalidation races; fresh SQL still fences every decision.
        if (!usable(key, candidate)) { local.invalidate(key); return; }
        try {
            redis.execute(WRITE, List.of(redisKey(key), redisKey(key) + ":revision"),
                    Long.toString(candidate.catalogVersion()), json.writeValueAsString(candidate));
        } catch (RuntimeException unavailable) { outcome("redis_unavailable"); }
    }

    public void invalidate(long revision) {
        if (revision < 1) throw new IllegalArgumentException("Invalid catalog revision");
        floor.accumulateAndGet(revision, Math::max);
        local.asMap().entrySet().removeIf(entry -> entry.getValue().catalogVersion() < floor.get());
    }

    private boolean usable(String key, OperationPolicyCandidate candidate) {
        return candidate != null && candidate.catalogVersion() >= floor.get()
                && "INDIVIDUAL".equals(candidate.snapshot().categoryKey())
                && "document-service".equals(candidate.snapshot().serviceId())
                && key.equals(candidate.snapshot().operationKey());
    }
    private static String redisKey(String key) { return "iam:operation-policy:v1:INDIVIDUAL:" + key; }
    private void outcome(String outcome) { metrics.counter("authorization.operation.cache", "outcome", outcome).increment(); }
    private static void outsideTransaction() {
        if (TransactionSynchronizationManager.isActualTransactionActive()) throw new IllegalStateException("Policy cache transport requires no transaction");
    }
}
