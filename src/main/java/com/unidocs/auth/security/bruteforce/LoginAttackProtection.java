package com.unidocs.auth.security.bruteforce;

import com.unidocs.auth.authentication.application.AuthenticationFailure;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

/** Distributed temporary login admission; it never changes durable account availability. */
@Component
public class LoginAttackProtection {
    private static final long MAX_SEQUENCE = 1000000000L;
    private static final String VALIDATE = """
            local maximum=1000000000
            local function invalid() error('Invalid login protection state') end
            local function number(value)
              if not value or not string.match(value,'^%d+$')
                or (string.len(value)>1 and string.sub(value,1,1)=='0') then invalid() end
              local n=tonumber(value)
              if not n or n<0 or n>maximum or n~=math.floor(n) then invalid() end
              return n
            end
            local function load(key)
              local kind=redis.call('TYPE',key).ok
              if kind=='none' then return nil end
              if kind~='hash' or redis.call('HLEN',key)~=4 or redis.call('PTTL',key)<=0 then invalid() end
              local fields=redis.call('HMGET',key,'generation','failures','cleared','inflight')
              local generation=fields[1]
              if not generation or string.len(generation)~=36 or not string.match(generation,'^[0-9a-f]+%-[0-9a-f]+%-[0-9a-f]+%-[0-9a-f]+%-[0-9a-f]+$')
                or string.sub(generation,9,9)~='-' or string.sub(generation,14,14)~='-'
                or string.sub(generation,19,19)~='-' or string.sub(generation,24,24)~='-' then invalid() end
              local failures=number(fields[2])
              local cleared=number(fields[3])
              local inflight=number(fields[4])
              if cleared>failures then invalid() end
              return {generation=generation,failures=failures,cleared=cleared,inflight=inflight}
            end
            """;
    private static final DefaultRedisScript<String> RESERVE = new DefaultRedisScript<>(VALIDATE + """
            local states={}
            local blocked=false
            for i=1,3 do
              states[i]=load(KEYS[i]) or {generation=ARGV[1],failures=0,cleared=0,inflight=0,new=true}
              local current=states[i]
              if current.failures>=maximum or current.inflight>=maximum then invalid() end
              if current.failures-current.cleared+current.inflight>=tonumber(ARGV[i+2]) then blocked=true end
            end
            if blocked then return 'blocked' end
            local result={'admitted'}
            for i=1,3 do
              local current=states[i]
              if current.new then
                redis.call('HSET',KEYS[i],'generation',current.generation,'failures',0,'cleared',0,'inflight',0)
                redis.call('PEXPIRE',KEYS[i],ARGV[2])
              end
              redis.call('HINCRBY',KEYS[i],'inflight',1)
              table.insert(result,current.generation)
              table.insert(result,tostring(current.failures))
            end
            return table.concat(result,'|')
            """, String.class);
    private static final DefaultRedisScript<String> COMPLETE = new DefaultRedisScript<>(VALIDATE + """
            local states={}
            for i=1,3 do
              states[i]=load(KEYS[i]) or false
              local current=states[i]
              local captured=number(ARGV[2*i+1])
              if current and current.generation==ARGV[2*i] then
                if current.inflight<1 or captured>current.failures then invalid() end
                if ARGV[1]=='failed' and current.failures>=maximum then invalid() end
              end
            end
            for i=1,3 do
              local current=states[i]
              if current and current.generation==ARGV[2*i] then
                redis.call('HINCRBY',KEYS[i],'inflight',-1)
                if ARGV[1]=='failed' then
                  redis.call('HINCRBY',KEYS[i],'failures',1)
                elseif i>1 then
                  local captured=number(ARGV[2*i+1])
                  if captured>current.cleared then redis.call('HSET',KEYS[i],'cleared',captured) end
                end
              end
            end
            return 'completed'
            """, String.class);
    private final StringRedisTemplate redis;
    private final LoginProtectionProperties properties;
    private final MeterRegistry metrics;
    private final ThreadLocal<Context> currentAction = new ThreadLocal<>();

    public LoginAttackProtection(StringRedisTemplate redis, LoginProtectionProperties properties, MeterRegistry metrics) {
        this.redis = Objects.requireNonNull(redis);
        this.properties = Objects.requireNonNull(properties);
        this.metrics = Objects.requireNonNull(metrics);
    }

    public <T> T protect(String peer, String canonicalSelector, Supplier<T> action) {
        Objects.requireNonNull(action);
        if (!properties.enabled()) return action.get();
        Context context = context(peer, canonicalSelector);
        Context previous = currentAction.get();
        if (context.equals(previous)) return action.get();
        List<String> keys = keys(context.peer(), context.selector());
        Ticket ticket = reserve(keys);
        currentAction.set(context);
        T response;
        try {
            response = action.get();
        } catch (RuntimeException failure) {
            complete(keys, ticket, false);
            outcome("failed");
            throw failure;
        } finally {
            if (previous == null) currentAction.remove();
            else currentAction.set(previous);
        }
        // Admission succeeded before authentication. Cleanup failure must not orphan a committed session.
        complete(keys, ticket, true);
        outcome("succeeded");
        return response;
    }

    /** Deterministic opaque keys, also permitting narrow test cleanup without clearing shared Redis. */
    public List<String> keys(String peer, String canonicalSelector) {
        Context context = context(peer, canonicalSelector);
        String prefix = properties.keyPrefix() + ":{login}:";
        return List.of(prefix + "ip:" + hash(context.peer()), prefix + "account:" + hash(context.selector()),
                prefix + "pair:" + hash(context.peer().length() + ":" + context.peer() + context.selector()));
    }

    private Ticket reserve(List<String> keys) {
        String result;
        try {
            result = redis.execute(RESERVE, keys, UUID.randomUUID().toString(),
                    Long.toString(properties.window().toMillis()), Integer.toString(properties.ipLimit()),
                    Integer.toString(properties.accountLimit()), Integer.toString(properties.pairLimit()));
            if ("blocked".equals(result)) {
                outcome("blocked");
                throw new AuthenticationFailure();
            }
            return Ticket.parse(result);
        } catch (AuthenticationFailure failure) {
            throw failure;
        } catch (RuntimeException unavailable) {
            outcome("unavailable");
            throw new AuthenticationFailure();
        }
    }

    private void complete(List<String> keys, Ticket ticket, boolean succeeded) {
        try {
            String result = redis.execute(COMPLETE, keys, succeeded ? "succeeded" : "failed",
                    ticket.first().generation(), Long.toString(ticket.first().sequence()),
                    ticket.second().generation(), Long.toString(ticket.second().sequence()),
                    ticket.third().generation(), Long.toString(ticket.third().sequence()));
            if (!"completed".equals(result)) throw new IllegalStateException("Invalid protection completion.");
        } catch (RuntimeException unavailable) {
            outcome("completion_unavailable");
        }
    }

    private static Context context(String peer, String selector) {
        if (selector == null || selector.isBlank() || selector.length() > 300
                || peer != null && peer.length() > 128) throw new AuthenticationFailure();
        String normalizedPeer = peer == null || peer.isBlank() ? "internal" : peer.strip().toLowerCase(Locale.ROOT);
        return new Context(normalizedPeer, selector);
    }

    private static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable.");
        }
    }

    private void outcome(String outcome) { metrics.counter("authentication.login.protection", "outcome", outcome).increment(); }
    private record Context(String peer, String selector) { }
    private record Snapshot(String generation, long sequence) { }
    private record Ticket(Snapshot first, Snapshot second, Snapshot third) {
        private static Ticket parse(String value) {
            if (value == null) throw new IllegalArgumentException("Invalid protection admission.");
            String[] fields = value.split("\\|", -1);
            if (fields.length != 7 || !"admitted".equals(fields[0])) throw new IllegalArgumentException("Invalid protection admission.");
            return new Ticket(snapshot(fields[1], fields[2]), snapshot(fields[3], fields[4]), snapshot(fields[5], fields[6]));
        }
        private static Snapshot snapshot(String generation, String sequence) {
            if (!generation.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                    || !sequence.matches("[0-9]{1,10}")) throw new IllegalArgumentException("Invalid protection snapshot.");
            long parsed = Long.parseLong(sequence);
            if (parsed > MAX_SEQUENCE) throw new IllegalArgumentException("Invalid protection sequence.");
            return new Snapshot(generation, parsed);
        }
    }
}
