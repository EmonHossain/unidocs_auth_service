package com.unidocs.auth.registration;

import com.unidocs.auth.RedisKafkaIntegrationTest;
import com.unidocs.auth.authorization.application.OrganizationSnapshotCache;
import com.unidocs.auth.authentication.api.LoginRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.organization.api.OrganizationRequest;
import com.unidocs.auth.organization.api.OrganizationResponse;
import com.unidocs.auth.organization.application.OrganizationFailure;
import com.unidocs.auth.organization.application.OrganizationService;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.registration.api.RegistrationCompletionRequest;
import com.unidocs.auth.registration.api.RegistrationCompletionResponse;
import com.unidocs.auth.registration.api.RegistrationRequest;
import com.unidocs.auth.registration.api.RegistrationResponse;
import com.unidocs.auth.registration.api.VerificationRequest;
import com.unidocs.auth.registration.application.RegistrationProvisioningService;
import com.unidocs.auth.registration.application.RegistrationService;
import io.micrometer.core.instrument.MeterRegistry;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.kafka.config.KafkaListenerEndpointRegistry;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.*;

@SpringBootTest(properties = {"auth.authorization.cache.enabled=true", "auth.authorization.cache.listener-enabled=true"})
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
class OrganizationCacheIntegrationTests extends RedisKafkaIntegrationTest {
    private static final String TOPIC = "iam-cache-test-" + UUID.randomUUID();
    @Autowired OrganizationSnapshotCache cache;
    @Autowired OrganizationService organizations;
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired AuthenticationService authentication;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired KafkaTemplate<String,String> kafka;
    @Autowired KafkaListenerEndpointRegistry listeners;
    @Autowired PlatformTransactionManager transactions;
    @Autowired MeterRegistry metrics;
    @MockitoSpyBean OrganizationRepository repository;
    @MockitoSpyBean StringRedisTemplate redis;
    private RegistrationCompletionResponse identity;
    private TokenResponse token;
    private OrganizationResponse organization;

    @DynamicPropertySource
    static void topic(DynamicPropertyRegistry registry) { registry.add("auth.outbox.topic", () -> TOPIC); }

    @BeforeAll
    static void createTopic() throws Exception {
        try (AdminClient admin = AdminClient.create(Map.of("bootstrap.servers", KAFKA.getBootstrapServers()))) {
            admin.createTopics(List.of(new NewTopic(TOPIC, 1, (short)1))).all().get(10,TimeUnit.SECONDS);
        }
    }
    @AfterAll
    static void deleteTopic() throws Exception {
        try (AdminClient admin = AdminClient.create(Map.of("bootstrap.servers", KAFKA.getBootstrapServers()))) {
            admin.deleteTopics(List.of(TOPIC)).all().get(10,TimeUnit.SECONDS);
        }
    }

    @BeforeEach
    void provision() {
        String email = UUID.randomUUID() + "@example.com";
        RegistrationResponse registration = registrations.register(new RegistrationRequest("Cache User",email,"test-password-long"));
        String proof = delivery.tokens.get(registration.id());
        registrations.verify(registration.id(), new VerificationRequest(proof));
        identity = provisioning.complete(registration.id(),new RegistrationCompletionRequest(proof));
        token = authentication.login(new LoginRequest(email,"test-password-long"));
        organization = organizations.create(token.sessionId(),identity.accountId(),new OrganizationRequest(identity.accountId(),
                UUID.randomUUID(),"Cache Organization","cache-"+UUID.randomUUID(), Organization.Type.COMPANY));
        cache.clearLocal();
        clearInvocations(repository, redis);
    }

    private OrganizationResponse read() {
        return organizations.get(token.sessionId(), identity.accountId(), identity.accountId(), organization.id());
    }
    private String key() { return OrganizationSnapshotCache.redisKey(new OrganizationSnapshotCache.Key(identity.accountId(),organization.id())); }

    @Test
    void caffeineAndRedisHitsStillCheckCurrentVisibilityAndAvoidFullRowHydration() {
        assertThat(read()).isEqualTo(organization);
        assertThat(read()).isEqualTo(organization);
        verify(repository,times(1)).visible(identity.accountId(),"LOGIN",organization.id(),null,1);
        verify(repository,times(2)).visibility(identity.accountId(),"LOGIN",organization.id());
        cache.clearLocal();
        assertThat(read()).isEqualTo(organization);
        verify(repository,times(1)).visible(identity.accountId(),"LOGIN",organization.id(),null,1);
        assertThat(redis.getExpire(key(),TimeUnit.MILLISECONDS)).isBetween(1L,30000L);
    }

    @ParameterizedTest
    @ValueSource(strings = {"UPDATE organization SET status='DISABLED'",
            "UPDATE organization_membership SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6),revoked_by=id",
            "UPDATE organization_auth_policy SET enabled=false", "UPDATE organization_auth_policy SET require_mfa=true",
            "UPDATE organization_auth_policy SET email_domain='example.com'"})
    void warmCacheCannotBypassCurrentMembershipOrPolicy(String mutation) {
        read();
        jdbc.update(mutation);
        assertThat(cache.find(identity.accountId(),organization.id())).isPresent();
        assertThatThrownBy(this::read).isInstanceOf(OrganizationFailure.class);
    }

    @Test
    void newerAuthorizationAndMembershipVersionsReplaceStaleSnapshots() {
        read();
        jdbc.update("UPDATE organization SET authorization_version=authorization_version+1,name='New Name'");
        jdbc.update("UPDATE organization_membership SET version=version+1,role='ADMIN'");
        OrganizationResponse fresh = read();
        assertThat(fresh.authorizationVersion()).isEqualTo(2);
        assertThat(fresh.membershipVersion()).isEqualTo(2);
        assertThat(fresh.role()).isEqualTo(OrganizationMembership.Role.ADMIN);
        assertThat(fresh.name()).isEqualTo("New Name");
        cache.put(organization);
        assertThat(cache.find(identity.accountId(),organization.id())).contains(fresh);
    }

    @ParameterizedTest
    @ValueSource(strings = {"UPDATE user_session SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6)",
            "UPDATE session_account_grant SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6),revocation_reason='LOGOUT'"})
    void warmCacheCannotBypassRevokedSessionOrGrant(String mutation) {
        read();
        jdbc.update(mutation);
        assertThat(cache.find(identity.accountId(),organization.id())).isPresent();
        assertThatThrownBy(this::read).isInstanceOf(AuthenticationFailure.class);
    }

    @Test
    void cachedRoleMustMatchCurrentDatabaseEvenWhenVersionsMatch() {
        OrganizationResponse forged = new OrganizationResponse(organization.id(),organization.name(),organization.slug(),
                organization.type(),organization.membershipId(),identity.accountId(),OrganizationMembership.Role.ADMIN,
                organization.membershipVersion(),organization.authorizationVersion(),organization.createdAt());
        cache.put(forged);
        assertThat(read().role()).isEqualTo(OrganizationMembership.Role.OWNER);
        verify(repository).visible(identity.accountId(),"LOGIN",organization.id(),null,1);
    }

    @Test
    void malformedSharedCacheFallsBackToAuthoritativeDatabase() {
        read();
        cache.clearLocal();
        redis.opsForHash().put(key(),"snapshot","malformed-json");
        assertThat(read()).isEqualTo(organization);
    }

    @Test
    @SuppressWarnings("unchecked")
    void redisOutageUsesMySqlAndNeverMovesCacheIoInsideTransaction() {
        doAnswer(invocation -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            throw new RedisConnectionFailureException("sensitive connection details");
        }).when(redis).execute(any(RedisScript.class),anyList(),any(Object[].class));
        assertThat(read()).isEqualTo(organization);
        jdbc.update("UPDATE organization_auth_policy SET enabled=false");
        assertThatThrownBy(this::read).isInstanceOf(OrganizationFailure.class);
    }

    @Test
    void cacheRejectsCallsInsideDatabaseTransactions() {
        new TransactionTemplate(transactions).executeWithoutResult(status ->
                assertThatThrownBy(() -> cache.find(identity.accountId(),organization.id())).isInstanceOf(IllegalStateException.class));
    }

    @Test
    void duplicateAndStaleKafkaEventsDoNotEvictCurrentSnapshots() throws Exception {
        await().atMost(Duration.ofSeconds(20)).until(() -> {
            java.util.Collection<org.apache.kafka.common.TopicPartition> assigned = listeners.getListenerContainer("organizationSnapshotInvalidation").getAssignedPartitions();
            return assigned != null && !assigned.isEmpty();
        });
        read();
        jdbc.update("UPDATE organization SET authorization_version=2");
        sendVersion(2);
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> assertThat(redis.opsForValue()
                .get(OrganizationSnapshotCache.floorKey(organization.id()))).isEqualTo("2"));
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertThat(cache.find(identity.accountId(),organization.id())).isEmpty());
        OrganizationResponse fresh = read();
        double invalidations = metrics.get("authorization.snapshot").tag("outcome","invalidation").counter().count();
        sendVersion(2);
        sendVersion(1);
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() -> assertThat(metrics.get("authorization.snapshot")
                .tag("outcome","invalidation").counter().count()).isGreaterThanOrEqualTo(invalidations+2));
        cache.invalidate(organization.id(),1);
        assertThat(cache.find(identity.accountId(),organization.id())).contains(fresh);
        assertThat(redis.opsForValue().get(OrganizationSnapshotCache.floorKey(organization.id()))).isEqualTo("2");
        cache.put(organization);
        assertThat(cache.find(identity.accountId(),organization.id())).contains(fresh);
    }

    @Test
    void redisVersionComparisonPreservesLongPrecision() {
        long version = 9007199254740993L;
        OrganizationResponse high = new OrganizationResponse(organization.id(),organization.name(),organization.slug(),
                organization.type(),organization.membershipId(),identity.accountId(),organization.role(),1,version,organization.createdAt());
        cache.put(high);
        cache.put(organization);
        cache.clearLocal();
        assertThat(cache.find(identity.accountId(),organization.id())).contains(high);
        cache.invalidate(organization.id(),version+1);
        cache.put(high);
        assertThat(cache.find(identity.accountId(),organization.id())).isEmpty();
    }

    private void sendVersion(long version) throws Exception {
        ProducerRecord<String,String> event = new ProducerRecord<>(TOPIC,"ORGANIZATION:"+organization.id(),"{}");
        event.headers().add("aggregateType","ORGANIZATION".getBytes(StandardCharsets.UTF_8));
        event.headers().add("eventType","ORGANIZATION_MEMBERSHIP_ACTIVATED".getBytes(StandardCharsets.UTF_8));
        event.headers().add("aggregateId",organization.id().toString().getBytes(StandardCharsets.UTF_8));
        event.headers().add("aggregateVersion",Long.toString(version).getBytes(StandardCharsets.UTF_8));
        kafka.send(event).get(10,TimeUnit.SECONDS);
    }
}
