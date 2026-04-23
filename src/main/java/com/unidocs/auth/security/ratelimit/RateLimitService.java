package com.unidocs.auth.security.ratelimit;
import java.util.List;
import jakarta.servlet.http.HttpServletRequest;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;
@Service
public class RateLimitService {
    private static final DefaultRedisScript<Long> ADMIT = new DefaultRedisScript<>("""
            local limit=tonumber(ARGV[1])
            local window=tonumber(ARGV[2])
            local value=redis.call('GET',KEYS[1])
            if not value then
              redis.call('SET',KEYS[1],'1','PX',window)
              return 0
            end
            if not string.match(value,'^[1-9]%d*$') then error('Invalid rate limit state') end
            local count=tonumber(value)
            local ttl=redis.call('PTTL',KEYS[1])
            if not count or count>1000000 or ttl<=0 then error('Invalid rate limit state') end
            if count>=limit then return ttl end
            redis.call('INCR',KEYS[1])
            return 0
            """, Long.class);
    private final StringRedisTemplate redis;
    private final RateLimitProperties properties;
    private final RateLimitKeyResolver keys;
    private final MeterRegistry metrics;
    public RateLimitService(StringRedisTemplate redis, RateLimitProperties properties,
                            RateLimitKeyResolver keys, MeterRegistry metrics) {
        this.redis = redis; this.properties = properties; this.keys = keys; this.metrics = metrics;
    }
    public void check(RateLimitPolicy policy, HttpServletRequest request) {
        if (!properties.enabled()) return;
        Long result;
        try {
            result = redis.execute(ADMIT, List.of(keys.resolve(properties, policy, request)),
                    Integer.toString(properties.limit(policy)), Long.toString(properties.window().toMillis()));
            if (result == null || result < 0 || result > properties.window().toMillis()) {
                throw new RateLimitUnavailableException();
            }
        } catch (RuntimeException unavailable) {
            metrics.counter("auth.rate_limit", "policy", policy.name(), "outcome", "unavailable").increment();
            throw new RateLimitUnavailableException();
        }
        if (result > 0) {
            metrics.counter("auth.rate_limit", "policy", policy.name(), "outcome", "blocked").increment();
            throw new RateLimitException((result + 999) / 1000);
        }
        metrics.counter("auth.rate_limit", "policy", policy.name(), "outcome", "allowed").increment();
    }
}
