package com.unidocs.auth.authorization.application;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.unidocs.auth.organization.api.OrganizationResponse;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.json.JsonMapper;

/** IAM alone writes this shared projection; every caller must validate current MySQL visibility. */
@Component
public class OrganizationSnapshotCache implements OrganizationSnapshotStore {
    public record Key(UUID account, UUID organization) { }
    private final Cache<Object, Object> snapshots;
    private final Cache<UUID, Long> floors = Caffeine.newBuilder().maximumSize(10000)
            .expireAfterAccess(Duration.ofMinutes(10)).build();
    private final StringRedisTemplate redis;
    private final JsonMapper json;
    private final MeterRegistry metrics;
    private final boolean enabled;
    private static final String COMPARE = """
            local function greater(a,b)
              return string.len(a)>string.len(b) or (string.len(a)==string.len(b) and a>b)
            end
            """;
    private static final DefaultRedisScript<String> READ = new DefaultRedisScript<>(COMPARE + """
            local version=redis.call('HGET',KEYS[1],'organizationVersion')
            local floor=redis.call('GET',KEYS[2])
            if version and floor and greater(floor,version) then return nil end
            return redis.call('HGET',KEYS[1],'snapshot')
            """, String.class);
    private static final DefaultRedisScript<Long> WRITE = new DefaultRedisScript<>(COMPARE + """
            local floor=redis.call('GET',KEYS[2])
            local current=redis.call('HGET',KEYS[1],'organizationVersion')
            local member=redis.call('HGET',KEYS[1],'membershipVersion')
            if (floor and greater(floor,ARGV[1])) or (current and greater(current,ARGV[1]))
              or (member and greater(member,ARGV[2])) then return 0 end
            redis.call('HSET',KEYS[1],'organizationVersion',ARGV[1],'membershipVersion',ARGV[2],'snapshot',ARGV[3])
            redis.call('PEXPIRE',KEYS[1],ARGV[4])
            return 1
            """, Long.class);
    private static final DefaultRedisScript<String> ADVANCE = new DefaultRedisScript<>(COMPARE + """
            local current=redis.call('GET',KEYS[1])
            if not current or greater(ARGV[1],current) then
              redis.call('SET',KEYS[1],ARGV[1],'PX',600000)
              return ARGV[1]
            end
            return current
            """, String.class);

    public OrganizationSnapshotCache(CacheManager caches, StringRedisTemplate redis, JsonMapper json,
            MeterRegistry metrics, @Value("${auth.authorization.cache.enabled:false}") boolean enabled) {
        this.snapshots = ((CaffeineCache) Objects.requireNonNull(caches.getCache("organization-entitlements"))).getNativeCache();
        this.redis = redis;
        this.json = json;
        this.metrics = metrics;
        this.enabled = enabled;
    }

    @Override
    public boolean enabled() { return enabled; }

    @Override
    public Optional<OrganizationResponse> find(UUID account, UUID organization) {
        if (!enabled) return Optional.empty();
        outsideTransaction();
        Key key = new Key(account, organization);
        OrganizationResponse local = (OrganizationResponse) snapshots.getIfPresent(key);
        if (usable(local, key)) {
            outcome("caffeine_hit");
            return Optional.of(local);
        }
        snapshots.invalidate(key);
        try {
            String raw = redis.execute(READ, List.of(redisKey(key), floorKey(organization)));
            if (raw != null && raw.length() <= 8192) {
                OrganizationResponse shared = json.readValue(raw, OrganizationResponse.class);
                if (usable(shared, key)) {
                    localPut(key, shared);
                    outcome("redis_hit");
                    return Optional.of(shared);
                }
                outcome("invalid_snapshot");
            }
        } catch (RuntimeException failure) {
            outcome("redis_unavailable"); // No errors or record data are logged.
        }
        outcome("miss");
        return Optional.empty();
    }

    @Override
    public void put(OrganizationResponse response) {
        if (!enabled) return;
        outsideTransaction();
        Key key = new Key(response.accountId(), response.id());
        if (!usable(response, key)) return;
        try {
            Long stored = redis.execute(WRITE, List.of(redisKey(key), floorKey(response.id())),
                    Long.toString(response.authorizationVersion()), Long.toString(response.membershipVersion()),
                    json.writeValueAsString(response), Long.toString(ThreadLocalRandom.current().nextLong(20000, 30001)));
            if (!Long.valueOf(1).equals(stored)) {
                outcome("stale_write");
                return;
            }
        } catch (RuntimeException failure) {
            outcome("redis_unavailable"); // MySQL validation permits a disposable local-only snapshot.
        }
        localPut(key, response);
    }

    @Override
    public void invalidate(UUID organization, long version) {
        if (!enabled) return;
        outsideTransaction();
        if (version < 1) throw new IllegalArgumentException("Invalid authorization version.");
        long floor = version;
        try {
            String shared = redis.execute(ADVANCE, List.of(floorKey(organization)), Long.toString(version));
            floor = Math.max(version, Long.parseLong(shared));
        } catch (RuntimeException failure) {
            outcome("redis_unavailable");
        }
        long next = floor;
        floors.asMap().compute(organization, (id, current) -> {
            long accepted = current == null ? next : Math.max(current, next);
            snapshots.asMap().entrySet().removeIf(entry -> entry.getKey() instanceof Key key
                    && key.organization().equals(id) && entry.getValue() instanceof OrganizationResponse response
                    && response.authorizationVersion() < accepted);
            return accepted;
        });
        outcome("invalidation");
    }

    public void clearLocal() { snapshots.invalidateAll(); } // Empty-pod behavior, also useful in integration tests.

    private void localPut(Key key, OrganizationResponse response) {
        floors.asMap().compute(key.organization(), (id, floor) -> {
            if (floor == null || response.authorizationVersion() >= floor) {
                snapshots.asMap().compute(key, (ignored, current) -> {
                    if (current instanceof OrganizationResponse existing
                            && (existing.authorizationVersion() > response.authorizationVersion()
                            || existing.membershipVersion() > response.membershipVersion())) return current;
                    return response;
                });
            }
            return floor;
        });
    }

    private boolean usable(OrganizationResponse response, Key key) {
        Long floor = floors.getIfPresent(key.organization());
        return response != null && key.account().equals(response.accountId()) && key.organization().equals(response.id())
                && response.membershipId() != null && response.role() != null && response.type() != null
                && response.createdAt() != null && response.name() != null && response.slug() != null
                && response.membershipVersion() >= 1 && response.authorizationVersion() >= 1
                && (floor == null || response.authorizationVersion() >= floor);
    }

    public static String redisKey(Key key) {
        return "iam:organization-entitlement:v1:{" + key.organization() + "}:" + key.account();
    }
    public static String floorKey(UUID organization) {
        return "iam:organization-version:v1:{" + organization + "}";
    }
    private void outcome(String outcome) { metrics.counter("authorization.snapshot", "outcome", outcome).increment(); }
    private static void outsideTransaction() {
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("Authorization cache I/O cannot run inside a database transaction.");
        }
    }
}
