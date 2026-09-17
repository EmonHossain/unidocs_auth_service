package com.unidocs.auth.registration;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.*;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.*;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.api.RegistrationResponse;
import com.unidocs.auth.registration.api.VerificationRequest;
import com.unidocs.auth.registration.application.*;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
@ExtendWith(OutputCaptureExtension.class)
class RegistrationIntegrationTests extends MySqlIntegrationTest {
    @Autowired RegistrationService service;
    @Autowired CapturingDelivery delivery;
    @Autowired PasswordEncoder passwords;
    @Autowired MockMvc mvc;
    @Autowired org.springframework.transaction.PlatformTransactionManager transactionManager;

    private RegistrationResponse register() {
        return service.register(new RegistrationRequest("Test User", UUID.randomUUID() + "@example.com",
                "test-password-long"));
    }

    private Object binary(UUID id) {
        return java.nio.ByteBuffer.allocate(16).putLong(id.getMostSignificantBits())
                .putLong(id.getLeastSignificantBits()).array();
    }

    @Test
    void registrationApiHashesSecretsAndOnlyVerificationCanReachVerified(CapturedOutput output) throws Exception {
        String email = UUID.randomUUID() + "@example.com";
        MvcResult result = mvc.perform(post("/api/v1/registrations").contentType(MediaType.APPLICATION_JSON)
                .content("{\"displayName\":\"User\",\"email\":\"" + email
                        + "\",\"password\":\"test-password-long\"}"))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.status").value("PENDING_VERIFICATION"))
                .andExpect(jsonPath("$.token").doesNotExist()).andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andExpect(header().string("Cache-Control", "no-store")).andReturn();
        UUID id = UUID.fromString(result.getResponse().getHeader("Location").replace("/api/v1/registrations/", ""));
        String token = delivery.tokens.get(id);
        String hash = jdbc.queryForObject("SELECT password_hash FROM pending_registration WHERE id = ?",
                String.class, binary(id));
        assertThat(passwords.matches("test-password-long", hash)).isTrue();
        assertThat(new VerificationTokens().matches(token, jdbc.queryForObject("SELECT token_hash FROM registration_verification WHERE pending_registration_id = ?",
                String.class, binary(id)))).isTrue();
        assertThat(token).matches("[0-9]{6}");
        assertThat(jdbc.queryForObject("SELECT TIMESTAMPDIFF(SECOND, created_at, expires_at) FROM registration_verification WHERE pending_registration_id=?", Integer.class, binary(id))).isEqualTo(300);
        mvc.perform(get("/api/v1/me").header("X-User-Id", id.toString())).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/registrations/" + id + "/verify").contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\"" + token + "\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("VERIFIED"));
        assertThat(jdbc.queryForObject("SELECT completed_at FROM pending_registration WHERE id = ?",
                java.sql.Timestamp.class, binary(id))).isNull();
        assertThatThrownBy(() -> service.verify(id, new VerificationRequest(token)))
                .isInstanceOf(RegistrationException.class);
        assertThat(output).doesNotContain(token, "test-password-long");
    }

    @Test
    void httpRegistrationNormalizesEmailBeforeValidationAndPreservesPasswordWhitespace() throws Exception {
        String canonicalEmail = UUID.randomUUID() + "@example.com";
        String suppliedEmail = "  " + canonicalEmail.toUpperCase(Locale.ROOT) + "  ";
        String originalPassword = "  registration-password-long  ";
        MvcResult registration = mvc.perform(post("/api/v1/registrations").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"User\",\"email\":\"" + suppliedEmail
                                + "\",\"password\":\"" + originalPassword + "\"}"))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.status").value("PENDING_VERIFICATION"))
                .andReturn();
        UUID id = UUID.fromString(registration.getResponse().getHeader("Location")
                .replace("/api/v1/registrations/", ""));
        assertThat(jdbc.queryForObject("SELECT identifier FROM pending_registration WHERE id = ?",
                String.class, binary(id))).isEqualTo(canonicalEmail);
        assertThat(jdbc.queryForObject("SELECT destination FROM registration_verification WHERE pending_registration_id = ?",
                String.class, binary(id))).isEqualTo(canonicalEmail);
        assertThat(delivery.destinations.get(id)).isEqualTo(canonicalEmail);
        String hash = jdbc.queryForObject("SELECT password_hash FROM pending_registration WHERE id = ?",
                String.class, binary(id));
        assertThat(hash).isNotEqualTo(originalPassword);
        assertThat(passwords.matches(originalPassword, hash)).isTrue();
        assertThat(passwords.matches(originalPassword.strip(), hash)).isFalse();
        String proof = "{\"token\":\"" + delivery.tokens.get(id) + "\"}";
        mvc.perform(post("/api/v1/registrations/" + id + "/verify").contentType(MediaType.APPLICATION_JSON).content(proof))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("VERIFIED"));
        mvc.perform(post("/api/v1/registrations/" + id + "/complete").contentType(MediaType.APPLICATION_JSON).content(proof))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("COMPLETED"));
        assertThat(jdbc.queryForList("SELECT identifier FROM login_identity WHERE type = 'EMAIL'", String.class))
                .containsExactly(canonicalEmail);
        assertThat(jdbc.queryForList("SELECT value FROM user_contact WHERE type = 'EMAIL'", String.class))
                .containsExactly(canonicalEmail);
        assertThat(jdbc.queryForObject("SELECT password_hash FROM login_identity WHERE identifier = ?",
                String.class, canonicalEmail)).isEqualTo(hash);
    }

    @Test
    void attemptsPersistDespiteFailureAndFifthFailureLocksToken() {
        RegistrationResponse registration = register();
        for (int i = 0; i < 5; i++) {
            assertThatThrownBy(() -> service.verify(registration.id(), new VerificationRequest("wrong")))
                    .isInstanceOf(RegistrationException.class);
        }
        assertThat(jdbc.queryForObject("SELECT attempt_count FROM registration_verification WHERE pending_registration_id = ?",
                Integer.class, binary(registration.id()))).isEqualTo(5);
        assertThat(jdbc.queryForObject("SELECT status FROM registration_verification WHERE pending_registration_id = ?",
                String.class, binary(registration.id()))).isEqualTo("FAILED");
        assertThatThrownBy(() -> service.verify(registration.id(), new VerificationRequest(delivery.tokens.get(registration.id()))))
                .isInstanceOf(RegistrationException.class);
    }

    @Test
    void expiredVerificationAndRegistrationPersistExpiration() {
        RegistrationResponse registration = register();
        jdbc.update("UPDATE registration_verification SET expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND WHERE pending_registration_id = ?",
                binary(registration.id()));
        assertThatThrownBy(() -> service.verify(registration.id(), new VerificationRequest(delivery.tokens.get(registration.id()))))
                .isInstanceOf(RegistrationException.class);
        assertThat(jdbc.queryForObject("SELECT status FROM registration_verification WHERE pending_registration_id = ?",
                String.class, binary(registration.id()))).isEqualTo("EXPIRED");
        jdbc.update("UPDATE pending_registration SET expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND WHERE id = ?",
                binary(registration.id()));
        assertThatThrownBy(() -> service.verify(registration.id(), new VerificationRequest(delivery.tokens.get(registration.id()))))
                .isInstanceOf(RegistrationException.class);
        assertThat(jdbc.queryForObject("SELECT status FROM pending_registration WHERE id = ?",
                String.class, binary(registration.id()))).isEqualTo("EXPIRED");
    }

    @Test
    void concurrentCorrectAttemptsConsumeTokenOnlyOnce() throws Exception {
        RegistrationResponse registration = register();
        VerificationRequest request = new VerificationRequest(delivery.tokens.get(registration.id()));
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Callable<Boolean> verify = () -> {
                start.await();
                try { service.verify(registration.id(), request); return true; }
                catch (RegistrationException exception) { return false; }
            };
            Future<Boolean> first = executor.submit(verify);
            Future<Boolean> second = executor.submit(verify);
            start.countDown();
            assertThat(List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(true, false);
        }
    }

    @Test
    void outerTransactionsAreRejectedBeforeEmailOrPersistence() {
        int count = jdbc.queryForObject("SELECT COUNT(*) FROM pending_registration", Integer.class);
        TransactionTemplate transactions = new org.springframework.transaction.support.TransactionTemplate(transactionManager);
        assertThatThrownBy(() -> transactions.execute(status -> register()))
                .isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM pending_registration", Integer.class)).isEqualTo(count);
    }

    @Test
    void malformedRequestsAndUnknownRegistrationHaveSanitizedErrors() throws Exception {
        mvc.perform(post("/api/v1/registrations").contentType(MediaType.APPLICATION_JSON)
                .content("{\"displayName\":\"User\",\"email\":\"bad\",\"password\":\"sensitive\"}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("sensitive"))));
        mvc.perform(post("/api/v1/registrations/" + UUID.randomUUID() + "/verify")
                .contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"secret\"}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.requestId").exists());
        assertThatThrownBy(() -> service.register(new RegistrationRequest("User", "bad", "short")))
                .isInstanceOf(RegistrationException.class);
    }

    @Test
    void smtpFailureLeavesCommittedPendingStateAndReturnsSanitized503(CapturedOutput output) throws Exception {
        int count = jdbc.queryForObject("SELECT COUNT(*) FROM pending_registration", Integer.class);
        delivery.fail = true;
        try {
            mvc.perform(post("/api/v1/registrations").contentType(MediaType.APPLICATION_JSON)
                    .content("{\"displayName\":\"User\",\"email\":\"smtp-failure@example.com\",\"password\":\"a-long-test-password\"}"))
                    .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.status").value(503))
                    .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("smtp-secret"))));
        } finally { delivery.fail = false; }
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM pending_registration", Integer.class)).isEqualTo(count + 1);
        assertThat(jdbc.queryForObject("SELECT status FROM pending_registration WHERE identifier = 'smtp-failure@example.com'",
                String.class)).isEqualTo("PENDING_VERIFICATION");
        assertThat(output).doesNotContain("smtp-secret", "a-long-test-password");
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class DeliveryConfiguration {
        @Bean CapturingDelivery verificationDelivery() { return new CapturingDelivery(); }
    }

    static class CapturingDelivery implements VerificationDelivery {
        final Map<UUID, String> tokens = new ConcurrentHashMap<>();
        final Map<UUID, String> destinations = new ConcurrentHashMap<>();
        boolean fail;
        @Override public void deliver(String destination, UUID id, String token, Instant expiry) {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            if (fail) { throw new IllegalStateException("smtp-secret"); }
            tokens.put(id, token);
            destinations.put(id, destination);
        }
    }
}
