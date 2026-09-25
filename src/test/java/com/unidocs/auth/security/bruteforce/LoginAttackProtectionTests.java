package com.unidocs.auth.security.bruteforce;

import com.unidocs.auth.authentication.application.AuthenticationFailure;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LoginAttackProtectionTests {
    private static final String GENERATION = "11111111-1111-1111-1111-111111111111";
    private static final String ADMITTED = "admitted|" + GENERATION + "|2|" + GENERATION + "|3|" + GENERATION + "|1";
    @Mock private StringRedisTemplate redis;
    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();

    private LoginAttackProtection protection(boolean enabled) {
        return new LoginAttackProtection(redis, new LoginProtectionProperties(enabled,"auth:login:v1",Duration.ofMinutes(15),50,10,5),metrics);
    }

    @Test
    void blockedAdmissionNeverInvokesCredentialAction() {
        when(redis.execute(any(RedisScript.class),anyList(),any(Object[].class))).thenReturn("blocked");
        AtomicInteger actions = new AtomicInteger();
        assertThatThrownBy(() -> protection(true).protect("192.0.2.1","email:user@example.test",actions::incrementAndGet))
                .isExactlyInstanceOf(AuthenticationFailure.class).hasMessage("Authentication failed.");
        assertThat(actions.get()).isZero();
        verify(redis,times(1)).execute(any(RedisScript.class),anyList(),any(Object[].class));
        assertThat(metrics.get("authentication.login.protection").tag("outcome","blocked").counter().count()).isEqualTo(1);
    }

    @Test
    void admissionOutageNeverInvokesCredentialActionOrExposesRedisMessage() {
        when(redis.execute(any(RedisScript.class),anyList(),any(Object[].class))).thenThrow(new IllegalStateException("private Redis details"));
        AtomicInteger actions = new AtomicInteger();
        assertThatThrownBy(() -> protection(true).protect("192.0.2.1","email:user@example.test",actions::incrementAndGet))
                .isExactlyInstanceOf(AuthenticationFailure.class).hasMessage("Authentication failed.");
        assertThat(actions.get()).isZero();
        assertThat(metrics.get("authentication.login.protection").tag("outcome","unavailable").counter().count()).isEqualTo(1);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings={"allow","admitted","admitted|bad|1|bad|1|bad|1",
            "admitted|11111111-1111-1111-1111-111111111111|-1|11111111-1111-1111-1111-111111111111|0|11111111-1111-1111-1111-111111111111|0",
            "admitted|11111111-1111-1111-1111-111111111111|1000000001|11111111-1111-1111-1111-111111111111|0|11111111-1111-1111-1111-111111111111|0"})
    void malformedAdmissionResultsFailClosed(String result) {
        when(redis.execute(any(RedisScript.class),anyList(),any(Object[].class))).thenReturn(result);
        AtomicInteger actions = new AtomicInteger();
        assertThatThrownBy(() -> protection(true).protect("192.0.2.1","account:known",actions::incrementAndGet)).isInstanceOf(AuthenticationFailure.class);
        assertThat(actions.get()).isZero();
    }

    @Test
    void successReturnsCommittedResponseDespiteCompletionOutage() {
        when(redis.execute(any(RedisScript.class),anyList(),any(Object[].class))).thenReturn(ADMITTED).thenThrow(new IllegalStateException("Redis outage"));
        assertThat(protection(true).protect("192.0.2.1","account:known",() -> "committed token")).isEqualTo("committed token");
        assertThat(metrics.get("authentication.login.protection").tag("outcome","completion_unavailable").counter().count()).isEqualTo(1);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings={"invalid","blocked"})
    void malformedCompletionStillReturnsCommittedResponse(String result) {
        when(redis.execute(any(RedisScript.class),anyList(),any(Object[].class))).thenReturn(ADMITTED,result);
        assertThat(protection(true).protect("192.0.2.1","account:known",() -> "committed token")).isEqualTo("committed token");
        assertThat(metrics.get("authentication.login.protection").tag("outcome","completion_unavailable").counter().count()).isEqualTo(1);
    }

    @Test
    void authenticationFailureRemainsGenericWhenCompletionFails() {
        when(redis.execute(any(RedisScript.class),anyList(),any(Object[].class))).thenReturn(ADMITTED).thenThrow(new IllegalStateException("Redis outage"));
        AuthenticationFailure original = new AuthenticationFailure();
        assertThatThrownBy(() -> protection(true).protect("192.0.2.1","account:known",() -> { throw original; })).isSameAs(original);
    }

    @Test
    void successfulAndFailedActionsUseDistinctCompletionSignals() {
        when(redis.execute(any(RedisScript.class),anyList(),any(Object[].class))).thenReturn(ADMITTED,"completed",ADMITTED,"completed");
        LoginAttackProtection protection = protection(true);
        protection.protect("192.0.2.1","account:known",() -> "ok");
        assertThatThrownBy(() -> protection.protect("192.0.2.1","account:known",() -> { throw new AuthenticationFailure(); })).isInstanceOf(AuthenticationFailure.class);
        verify(redis).execute(any(RedisScript.class),anyList(),eq("succeeded"),eq(GENERATION),eq("2"),eq(GENERATION),eq("3"),eq(GENERATION),eq("1"));
        verify(redis).execute(any(RedisScript.class),anyList(),eq("failed"),eq(GENERATION),eq("2"),eq(GENERATION),eq("3"),eq(GENERATION),eq("1"));
    }

    @Test
    void exactNestedContextIsProtectedOnceAndFinallyRemoved() {
        when(redis.execute(any(RedisScript.class),anyList(),any(Object[].class))).thenReturn(ADMITTED,"completed",ADMITTED,"completed");
        LoginAttackProtection protection = protection(true);
        assertThat(protection.protect(" 192.0.2.1 ","account:known",() -> protection.protect("192.0.2.1","account:known",() -> "ok"))).isEqualTo("ok");
        protection.protect("192.0.2.1","account:known",() -> "next");
        verify(redis,times(4)).execute(any(RedisScript.class),anyList(),any(Object[].class));
    }

    @Test
    void differentNestedSelectorHasItsOwnAdmission() {
        when(redis.execute(any(RedisScript.class),anyList(),any(Object[].class))).thenReturn(ADMITTED,ADMITTED,"completed","completed");
        LoginAttackProtection protection = protection(true);
        protection.protect("192.0.2.1","account:first",() -> protection.protect("192.0.2.1","account:second",() -> "ok"));
        verify(redis,times(4)).execute(any(RedisScript.class),anyList(),any(Object[].class));
    }

    @Test
    void failureRemovesNestedScopeBeforeNextCall() {
        when(redis.execute(any(RedisScript.class),anyList(),any(Object[].class))).thenReturn(ADMITTED,"completed","blocked");
        LoginAttackProtection protection = protection(true);
        assertThatThrownBy(() -> protection.protect("192.0.2.1","account:known",() -> { throw new AuthenticationFailure(); })).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(() -> protection.protect("192.0.2.1","account:known",() -> "must not run")).isInstanceOf(AuthenticationFailure.class);
        verify(redis,times(3)).execute(any(RedisScript.class),anyList(),any(Object[].class));
    }

    @Test
    void disabledExplicitOptOutDoesNotUseRedis() {
        assertThat(protection(false).protect("192.0.2.1","account:known",() -> "ok")).isEqualTo("ok");
        verifyNoInteractions(redis);
    }

    @Test
    void keysAreOpaqueStableAndShareOnlyTheIntendedDimensions() {
        LoginAttackProtection protection = protection(true);
        List<String> first = protection.keys(" 2001:DB8::1 ","email:user@example.test");
        assertThat(first).isEqualTo(protection.keys("2001:db8::1","email:user@example.test"));
        assertThat(first).allMatch(key -> key.matches("auth:login:v1:[{]login[}]:(ip|account|pair):[0-9a-f]{64}"));
        assertThat(first.toString()).doesNotContain("user@example.test","2001:");
        List<String> otherAccount = protection.keys("2001:db8::1","account:other");
        assertThat(otherAccount.get(0)).isEqualTo(first.get(0));
        assertThat(otherAccount.get(1)).isNotEqualTo(first.get(1));
        List<String> otherIp = protection.keys("192.0.2.1","email:user@example.test");
        assertThat(otherIp.get(1)).isEqualTo(first.get(1));
        assertThat(otherIp.get(2)).isNotEqualTo(first.get(2));
    }
}
