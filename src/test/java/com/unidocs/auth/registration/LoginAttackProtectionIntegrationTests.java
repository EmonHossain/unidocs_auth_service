package com.unidocs.auth.registration;

import com.unidocs.auth.RedisIntegrationTest;
import com.unidocs.auth.authentication.api.LoginRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.organization.api.OrganizationRequest;
import com.unidocs.auth.organization.api.OrganizationResponse;
import com.unidocs.auth.organization.application.OrganizationService;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.organization.employee.EmployeeRequests;
import com.unidocs.auth.organization.employee.EmployeeService;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.application.RegistrationService;
import com.unidocs.auth.registration.application.RegistrationProvisioningService;
import com.unidocs.auth.security.bruteforce.LoginAttackProtection;
import com.unidocs.auth.security.bruteforce.LoginProtectionProperties;
import com.jayway.jsonpath.JsonPath;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
class LoginAttackProtectionIntegrationTests extends RedisIntegrationTest {
    private static final String PREFIX = "auth:test:login:" + UUID.randomUUID();
    private static final String PASSWORD = "test-password-long";
    @Autowired MockMvc mvc;
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired org.springframework.context.ApplicationContext application;
    @Autowired OrganizationService organizations;
    @Autowired EmployeeService employees;
    @Autowired MeterRegistry metrics;
    @Autowired LoginAttackProtection protection;
    @MockitoSpyBean StringRedisTemplate redis;
    private String email;
    private RegistrationCompletionResponse identity;

    @DynamicPropertySource
    static void protectionProperties(DynamicPropertyRegistry registry) {
        registry.add("auth.login-protection.enabled", () -> true);
        registry.add("auth.login-protection.key-prefix", () -> PREFIX);
    }

    @BeforeEach void prepare() {
        clearTestKeys();
        email = UUID.randomUUID() + "@example.com";
        RegistrationResponse pending = registrations.register(new RegistrationRequest("Protected user", email, PASSWORD));
        String code = delivery.tokens.get(pending.id());
        registrations.verify(pending.id(), new VerificationRequest(code));
        identity = provisioning.complete(pending.id(), new RegistrationCompletionRequest(code));
    }
    @AfterEach void cleanup() { reset(redis); clearTestKeys(); }
    private void clearTestKeys() {
        Set<String> keys = redis.keys(PREFIX + "*");
        if (keys != null && !keys.isEmpty()) redis.delete(keys);
    }
    private int sessions() { return jdbc.queryForObject("SELECT COUNT(*) FROM user_session", Integer.class); }
    private String canonical() { return "account:" + identity.accountId(); }
    private LoginAttackProtection policy(int ip, int account, int pair) {
        return new LoginAttackProtection(redis, new LoginProtectionProperties(true, PREFIX,
                Duration.ofMinutes(15), ip, account, pair), metrics);
    }
    private void fail(LoginAttackProtection guarded, String peer, String selector) {
        assertThatThrownBy(() -> guarded.protect(peer, selector, () -> { throw new AuthenticationFailure(); }))
                .isInstanceOf(AuthenticationFailure.class);
    }
    private MvcResult emailLogin(String peer, String identifier, String password, int expected) throws Exception {
        return mvc.perform(post("/api/v1/auth/login").with(request -> { request.setRemoteAddr(peer); return request; })
                .contentType("application/json").content("{\"email\":\"" + identifier + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().is(expected)).andReturn();
    }
    private MvcResult accountLogin(String peer, UUID account, String password, int expected) throws Exception {
        return mvc.perform(post("/api/v1/auth/accounts/" + account + "/login")
                .with(request -> { request.setRemoteAddr(peer); return request; })
                .contentType("application/json").content("{\"password\":\"" + password + "\"}"))
                .andExpect(status().is(expected)).andReturn();
    }

    @Test void pairBlocksCorrectPasswordTemporarilyWithoutPersistedAccountLock() throws Exception {
        for (int index = 0; index < 5; index++) emailLogin("192.0.2.10", email, "wrong-password-long", 401);
        emailLogin("192.0.2.10", email, PASSWORD, 401);
        assertThat(sessions()).isZero();
        assertThat(jdbc.queryForObject("SELECT status FROM user_account WHERE id=?", String.class, bytes(identity.accountId())))
                .isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT status FROM login_identity WHERE account_id=?", String.class, bytes(identity.accountId())))
                .isEqualTo("ACTIVE");
        // A new peer can still authenticate before the higher account threshold is reached.
        emailLogin("192.0.2.11", email, PASSWORD, 200);
        emailLogin("192.0.2.10", email, PASSWORD, 401);
    }

    @Test void emailCaseAndAccountUuidShareAccountFailureBucket() throws Exception {
        for (int index = 0; index < 10; index++) {
            String peer = "192.0.2." + (20 + index);
            if (index % 2 == 0) emailLogin(peer, "  " + email.toUpperCase(Locale.ROOT) + "  ", "wrong-password-long", 401);
            else accountLogin(peer, identity.accountId(), "wrong-password-long", 401);
        }
        emailLogin("192.0.2.99", email, PASSWORD, 401);
        accountLogin("192.0.2.98", identity.accountId(), PASSWORD, 401);
        assertThat(sessions()).isZero();
    }

    @Test void forgedForwardingHeadersCannotEvadePeerBucket() throws Exception {
        for (int index = 0; index < 48; index++) {
            fail(protection, "192.0.2.40", "email:unknown-" + index + "@example.com");
        }
        for (String header : List.of("X-Forwarded-For", "Forwarded")) {
            mvc.perform(post("/api/v1/auth/login").with(request -> { request.setRemoteAddr("192.0.2.40"); return request; })
                    .header(header, "198.51.100.1").contentType("application/json")
                    .content("{\"email\":\"" + email + "\",\"password\":\"wrong-password-long\"}"))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/api/v1/auth/login").with(request -> { request.setRemoteAddr("192.0.2.40"); return request; })
                .header("X-Real-IP", "198.51.100.1").contentType("application/json")
                .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isUnauthorized());
        assertThat(sessions()).isZero();
        emailLogin("198.51.100.1", email, PASSWORD, 200);
    }

    @Test void unknownPendingDisabledAndWrongPasswordFailuresAreIndistinguishable() throws Exception {
        String pendingEmail = UUID.randomUUID() + "@example.com";
        registrations.register(new RegistrationRequest("Pending", pendingEmail, PASSWORD));
        List<Map<String, Object>> problems = new ArrayList<>();
        for (String identifier : List.of(email, "unknown@example.com", pendingEmail)) {
            problems.add(problem(emailLogin("192.0.2.50", identifier, "wrong-password-long", 401)));
        }
        jdbc.update("UPDATE login_identity SET status='DISABLED' WHERE account_id=?", bytes(identity.accountId()));
        problems.add(problem(emailLogin("192.0.2.51", email, PASSWORD, 401)));
        assertThat(problems).allSatisfy(problem -> assertThat(problem).isEqualTo(problems.getFirst()));
        assertThat(sessions()).isZero();
    }
    private Map<String, Object> problem(MvcResult result) throws Exception {
        Map<String, Object> response = new HashMap<>(JsonPath.<Map<String, Object>>read(result.getResponse().getContentAsString(), "$"));
        assertThat(response).containsKey("requestId");
        response.remove("requestId");
        return response;
    }

    @Test void ipLimitSpansDifferentSelectors() {
        LoginAttackProtection guarded = policy(3, 100, 100);
        for (int index = 0; index < 3; index++) fail(guarded, "192.0.2.60", "email:unknown-" + index);
        AtomicInteger calls = new AtomicInteger();
        assertThatThrownBy(() -> guarded.protect("192.0.2.60", "account:other", () -> calls.incrementAndGet()))
                .isInstanceOf(AuthenticationFailure.class);
        assertThat(calls).hasValue(0);
        assertThat(guarded.protect("192.0.2.61", "account:other", () -> true)).isTrue();
    }

    @Test void accountLimitSpansDifferentPeers() {
        LoginAttackProtection guarded = policy(100, 3, 100);
        for (int index = 0; index < 3; index++) fail(guarded, "192.0.2." + (70 + index), canonical());
        assertThatThrownBy(() -> guarded.protect("192.0.2.79", canonical(), () -> true)).isInstanceOf(AuthenticationFailure.class);
        assertThat(guarded.protect("192.0.2.79", "account:other", () -> true)).isTrue();
    }

    @Test void successClearsAccountAndPairButRetainsIpFailureHistory() {
        LoginAttackProtection guarded = policy(4, 3, 3);
        fail(guarded, "192.0.2.80", canonical());
        fail(guarded, "192.0.2.80", canonical());
        assertThat(guarded.protect("192.0.2.80", canonical(), () -> true)).isTrue();
        fail(guarded, "192.0.2.80", canonical());
        fail(guarded, "192.0.2.80", canonical());
        assertThatThrownBy(() -> guarded.protect("192.0.2.80", "account:other", () -> true)).isInstanceOf(AuthenticationFailure.class);
        assertThat(guarded.protect("192.0.2.81", canonical(), () -> true)).isTrue();
    }

    @Test void temporaryBlockHasBoundedExpiryWithoutExtendingOnRejectedAttempts() {
        LoginAttackProtection guarded = policy(100, 100, 1);
        fail(guarded, "192.0.2.90", canonical());
        Set<String> keys = redis.keys(PREFIX + "*");
        assertThat(keys).hasSize(3);
        Map<String, Long> ttl = new HashMap<>();
        for (String key : keys) {
            long milliseconds = redis.getExpire(key, TimeUnit.MILLISECONDS);
            assertThat(milliseconds).isPositive().isLessThanOrEqualTo(Duration.ofMinutes(15).toMillis());
            ttl.put(key, milliseconds);
        }
        assertThatThrownBy(() -> guarded.protect("192.0.2.90", canonical(), () -> true)).isInstanceOf(AuthenticationFailure.class);
        for (String key : keys) assertThat(redis.getExpire(key, TimeUnit.MILLISECONDS)).isLessThanOrEqualTo(ttl.get(key));
        for (String key : keys) redis.expire(key, Duration.ofMillis(1));
        org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(3)).until(() -> keys.stream().noneMatch(redis::hasKey));
        assertThat(guarded.protect("192.0.2.90", canonical(), () -> true)).isTrue();
    }

    @Test void parallelReservationsAdmitOnlyConfiguredBudget() throws Exception {
        LoginAttackProtection guarded = policy(100, 100, 3);
        AtomicInteger admitted = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(3);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch rejected = new CountDownLatch(9);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<Boolean>> futures = new ArrayList<>();
            for (int index = 0; index < 12; index++) {
                futures.add(executor.submit(() -> {
                    try {
                        guarded.protect("192.0.2.100", canonical(), () -> {
                            admitted.incrementAndGet(); entered.countDown();
                            try { if (!release.await(10, TimeUnit.SECONDS)) throw new AssertionError("Admission release timed out"); }
                            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
                            throw new AuthenticationFailure();
                        });
                        return true;
                    } catch (AuthenticationFailure denied) { rejected.countDown(); return false; }
                }));
            }
            try {
                assertThat(entered.await(10, TimeUnit.SECONDS)).isTrue();
                assertThat(rejected.await(10, TimeUnit.SECONDS)).isTrue();
                assertThat(admitted).hasValue(3);
            } finally { release.countDown(); }
            for (Future<Boolean> future : futures) assertThat(future.get(10, TimeUnit.SECONDS)).isFalse();
        }
        assertThatThrownBy(() -> guarded.protect("192.0.2.100", canonical(), () -> true)).isInstanceOf(AuthenticationFailure.class);
    }

    @Test void delayedSuccessDoesNotEraseNewerConcurrentFailures() throws Exception {
        LoginAttackProtection guarded = policy(100, 1, 100);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        // A higher-budget instance shares Redis generations while the original success is in flight.
        LoginAttackProtection concurrent = policy(100, 100, 100);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> success = executor.submit(() -> guarded.protect("192.0.2.110", canonical(), () -> {
                entered.countDown();
                try { if (!release.await(10, TimeUnit.SECONDS)) throw new AssertionError("Success release timed out"); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
                return true;
            }));
            try {
                assertThat(entered.await(10, TimeUnit.SECONDS)).isTrue();
                fail(concurrent, "192.0.2.111", canonical());
            } finally { release.countDown(); }
            assertThat(success.get(10, TimeUnit.SECONDS)).isTrue();
        }
        assertThatThrownBy(() -> guarded.protect("192.0.2.112", canonical(), () -> true)).isInstanceOf(AuthenticationFailure.class);
    }

    @Test void redisOutageFailsClosedWithoutIssuingSessionOrLeakingDetails() throws Exception {
        doThrow(new RedisConnectionFailureException("sensitive connection password"))
                .when(redis).execute(any(RedisScript.class), anyList(), any(Object[].class));
        MvcResult result = emailLogin("192.0.2.120", email, PASSWORD, 401);
        assertThat(result.getResponse().getContentAsString()).doesNotContain("sensitive", "password", email);
        assertThat(sessions()).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant", Integer.class)).isZero();
    }

    @Test void activatedEmployeeUsernameAndAccountUuidCannotBypassAccountThrottle() throws Exception {
        TokenResponse owner = authentication.login(new LoginRequest(email, PASSWORD));
        OrganizationResponse organization = organizations.create(owner.sessionId(), identity.accountId(),
                new OrganizationRequest(identity.accountId(), UUID.randomUUID(), "Protected company", "protected-" + UUID.randomUUID(), Organization.Type.COMPANY));
        TokenResponse administrator=ProfessionalFixture.administrator(application,owner,PASSWORD,organization.id());
        EmployeeRequests.Credentials employee = employees.create(administrator.sessionId(), administrator.loginAccountId(), organization.id(),
                new EmployeeRequests.Create(administrator.loginAccountId(), UUID.randomUUID(), "Employee"));
        employees.login(new EmployeeRequests.Login(employee.username(), employee.temporaryPassword(), "permanent-password-long"));
        for (int index = 0; index < 10; index++) {
            String peer = "192.0.2." + (130 + index);
            if (index % 2 == 0) accountLogin(peer, employee.accountId(), "wrong-password-long", 401);
            else mvc.perform(post("/api/v1/auth/employee-login").with(request -> { request.setRemoteAddr(peer); return request; })
                    .contentType("application/json").content("{\"username\":\"" + employee.username().toUpperCase(Locale.ROOT) + "\",\"password\":\"wrong-password-long\"}"))
                    .andExpect(status().isUnauthorized());
        }
        accountLogin("192.0.2.149", employee.accountId(), "permanent-password-long", 401);
        mvc.perform(post("/api/v1/auth/employee-login").with(request -> { request.setRemoteAddr("192.0.2.148"); return request; })
                .contentType("application/json").content("{\"username\":\"" + employee.username() + "\",\"password\":\"permanent-password-long\"}"))
                .andExpect(status().isUnauthorized());
        assertThat(sessions()).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT status FROM employee_activation WHERE account_id=?", String.class, bytes(employee.accountId())))
                .isEqualTo("ACTIVATED");
    }

    @ParameterizedTest
    @ValueSource(strings={"wrong-type", "malformed-hash", "noncanonical-number", "missing-ttl"})
    void corruptRedisStateDeniesBeforeActionWithoutRepairingExpiry(String corruption) {
        LoginAttackProtection guarded = policy(100, 100, 100);
        String key = guarded.keys("192.0.2.150", canonical()).getFirst();
        if (corruption.equals("wrong-type")) {
            redis.opsForValue().set(key, "invalid-type", Duration.ofMinutes(15));
        } else {
            redis.opsForHash().putAll(key, Map.of("generation", UUID.randomUUID().toString(),
                    "failures", corruption.equals("malformed-hash") ? "not-a-number"
                            : corruption.equals("noncanonical-number") ? "01" : "0",
                    "cleared", "0", "inflight", "0"));
            if (!corruption.equals("missing-ttl")) redis.expire(key, Duration.ofMinutes(15));
        }
        long originalTtl = redis.getExpire(key, TimeUnit.MILLISECONDS);
        AtomicInteger calls = new AtomicInteger();
        assertThatThrownBy(() -> guarded.protect("192.0.2.150", canonical(), () -> calls.incrementAndGet()))
                .isInstanceOf(AuthenticationFailure.class);
        assertThat(calls).hasValue(0);
        long currentTtl = redis.getExpire(key, TimeUnit.MILLISECONDS);
        if (originalTtl < 0) assertThat(currentTtl).isEqualTo(originalTtl);
        else assertThat(currentTtl).isPositive().isLessThanOrEqualTo(originalTtl);
        assertThat(redis.keys(PREFIX + "*")).containsExactly(key);
    }

    @Test void staleSuccessCannotModifyReplacementRedisGeneration() throws Exception {
        LoginAttackProtection guarded = policy(100, 100, 1);
        List<String> keys = guarded.keys("192.0.2.160", canonical());
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> oldSuccess = executor.submit(() -> guarded.protect("192.0.2.160", canonical(), () -> {
                entered.countDown();
                try { if (!release.await(10, TimeUnit.SECONDS)) throw new AssertionError("Stale success release timed out"); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
                return true;
            }));
            Map<String, Map<Object, Object>> replacement = new HashMap<>();
            try {
                assertThat(entered.await(10, TimeUnit.SECONDS)).isTrue();
                String oldGeneration = redis.opsForHash().get(keys.getFirst(), "generation").toString();
                for (String key : keys) redis.expire(key, Duration.ofMillis(1));
                org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(3)).until(() -> keys.stream().noneMatch(redis::hasKey));
                fail(guarded, "192.0.2.160", canonical());
                assertThat(redis.opsForHash().get(keys.getFirst(), "generation")).isNotEqualTo(oldGeneration);
                for (String key : keys) replacement.put(key, redis.opsForHash().entries(key));
            } finally { release.countDown(); }
            assertThat(oldSuccess.get(10, TimeUnit.SECONDS)).isTrue();
            for (String key : keys) assertThat(redis.opsForHash().entries(key)).isEqualTo(replacement.get(key));
        }
        assertThatThrownBy(() -> guarded.protect("192.0.2.160", canonical(), () -> true))
                .isInstanceOf(AuthenticationFailure.class);
    }

    @Test void redisOutageBlocksTemporaryEmployeeActivationBeforeCredentialReplacement() throws Exception {
        TokenResponse owner = authentication.login(new LoginRequest(email, PASSWORD));
        OrganizationResponse organization = organizations.create(owner.sessionId(), identity.accountId(),
                new OrganizationRequest(identity.accountId(), UUID.randomUUID(), "Protected company", "pending-" + UUID.randomUUID(), Organization.Type.COMPANY));
        TokenResponse administrator=ProfessionalFixture.administrator(application,owner,PASSWORD,organization.id());
        EmployeeRequests.Credentials employee = employees.create(administrator.sessionId(), administrator.loginAccountId(), organization.id(),
                new EmployeeRequests.Create(administrator.loginAccountId(), UUID.randomUUID(), "Pending employee"));
        Long originalVersion = jdbc.queryForObject("SELECT credential_version FROM login_identity WHERE account_id=?",
                Long.class, bytes(employee.accountId()));
        doThrow(new RedisConnectionFailureException("sensitive connection password"))
                .when(redis).execute(any(RedisScript.class), anyList(), any(Object[].class));
        MvcResult result = mvc.perform(post("/api/v1/auth/employee-login")
                .with(request -> { request.setRemoteAddr("192.0.2.170"); return request; })
                .contentType("application/json").content("{\"username\":\"" + employee.username()
                        + "\",\"password\":\"" + employee.temporaryPassword() + "\",\"newPassword\":\"permanent-password-long\"}"))
                .andExpect(status().isUnauthorized()).andReturn();
        assertThat(result.getResponse().getContentAsString()).doesNotContain("sensitive", employee.temporaryPassword(), "permanent-password-long");
        assertThat(jdbc.queryForObject("SELECT status FROM employee_activation WHERE account_id=?", String.class, bytes(employee.accountId())))
                .isEqualTo("PENDING");
        assertThat(jdbc.queryForObject("SELECT status FROM login_identity WHERE account_id=?", String.class, bytes(employee.accountId())))
                .isEqualTo("DISABLED");
        assertThat(jdbc.queryForObject("SELECT credential_version FROM login_identity WHERE account_id=?", Long.class, bytes(employee.accountId())))
                .isEqualTo(originalVersion);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant WHERE account_id=?", Integer.class, bytes(employee.accountId())))
                .isZero();
        assertThat(sessions()).isEqualTo(1);
    }

}
