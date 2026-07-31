package com.unidocs.auth.authorization.application;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import com.unidocs.auth.authorization.domain.*;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import tools.jackson.databind.json.JsonMapper;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class OperationPolicyCandidateCacheTests {
    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    private final OperationPolicyCandidateCache cache = new OperationPolicyCandidateCache(redis, JsonMapper.builder().findAndAddModules().build(), new SimpleMeterRegistry(), true);

    @Test void duplicateOrReorderedInvalidationsCannotRestoreStalePayloads() {
        cache.put(candidate(3));
        assertThat(cache.find("file.share")).isPresent();
        cache.invalidate(4); cache.invalidate(2); cache.put(candidate(3));
        assertThat(cache.find("file.share")).isEmpty();
        cache.put(candidate(5));
        assertThat(cache.find("file.share").orElseThrow().catalogVersion()).isEqualTo(5);
    }

    @Test void remoteCacheTransportIsNeverPerformedInsideSqlTransaction() {
        TransactionSynchronizationManager.setActualTransactionActive(true);
        try {
            assertThatThrownBy(() -> cache.find("file.share")).isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> cache.put(candidate(1))).isInstanceOf(IllegalStateException.class);
            verifyNoInteractions(redis);
        } finally { TransactionSynchronizationManager.setActualTransactionActive(false); }
    }

    @Test void redisReadFailureProducesCacheMissForAuthoritativeSqlLookup() {
        when(redis.opsForValue()).thenThrow(new org.springframework.data.redis.RedisConnectionFailureException("redis unavailable"));

        assertThat(cache.find("file.share")).isEmpty();
    }

    @Test void redisWriteFailureDoesNotEscapeTheAuthorizationRequest() {
        when(redis.execute(any(), anyList(), any())).thenThrow(
                new org.springframework.data.redis.RedisConnectionFailureException("redis unavailable"));

        assertThatCode(() -> cache.put(candidate(1))).doesNotThrowAnyException();
    }

    private OperationPolicyCandidate candidate(long version) {
        UUID authority = UUID.randomUUID();
        OperationPolicySnapshot snapshot = new OperationPolicySnapshot(UUID.randomUUID(), "document-service", "file.share", 1,
                UUID.randomUUID(), 1, "INDIVIDUAL", 1, UUID.randomUUID(), 1,
                new OperationAuthorityPolicy(Set.of(authority), AuthorityMatchMode.ALL_OF, false), Set.of(authority), Map.of(authority, 1L));
        return new OperationPolicyCandidate(snapshot, version, Map.of(authority, "file.share"), Set.of(authority));
    }
}
