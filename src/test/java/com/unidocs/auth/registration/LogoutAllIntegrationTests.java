package com.unidocs.auth.registration;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authentication.api.LoginRequest;
import com.unidocs.auth.authentication.api.RefreshRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.registration.api.RegistrationCompletionRequest;
import com.unidocs.auth.registration.api.RegistrationCompletionResponse;
import com.unidocs.auth.registration.api.RegistrationRequest;
import com.unidocs.auth.registration.api.RegistrationResponse;
import com.unidocs.auth.registration.api.VerificationRequest;
import com.unidocs.auth.registration.application.RegistrationProvisioningService;
import com.unidocs.auth.registration.application.RegistrationService;

import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
class LogoutAllIntegrationTests extends MySqlIntegrationTest {
    private static final String PASSWORD = "test-password-long";
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired MockMvc mvc;
    @Autowired com.unidocs.auth.account.application.LinkedAccountService linked;
    @Autowired org.springframework.security.crypto.password.PasswordEncoder passwords;
    @org.springframework.test.context.bean.override.mockito.MockitoSpyBean org.springframework.jdbc.core.JdbcTemplate observedJdbc;
    String email;
    RegistrationCompletionResponse owner;

    @BeforeEach
    void provisionOwner() {
        email = UUID.randomUUID() + "@example.com";
        owner = provision(email);
    }

    private RegistrationCompletionResponse provision(String address) {
        RegistrationResponse pending = registrations.register(new RegistrationRequest("Human", address, PASSWORD));
        String proof = delivery.tokens.get(pending.id());
        registrations.verify(pending.id(), new VerificationRequest(proof));
        return provisioning.complete(pending.id(), new RegistrationCompletionRequest(proof));
    }

    private TokenResponse login() { return authentication.login(new LoginRequest(email, PASSWORD)); }

    @Test
    void revokesEveryDeviceAndRotatedRefreshButPreservesOtherHuman() throws Exception {
        TokenResponse first = login();
        TokenResponse second = login();
        TokenResponse rotated = authentication.refresh(new RefreshRequest(second.refreshToken()));
        String otherEmail = UUID.randomUUID() + "@example.com";
        RegistrationCompletionResponse other = provision(otherEmail);
        TokenResponse stranger = authentication.login(new LoginRequest(otherEmail, PASSWORD));


        org.springframework.test.web.servlet.MvcResult action = mvc.perform(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/v1/auth/logout-all")
                                .header("Authorization", "Bearer " + first.accessToken()))
                .andExpect(status().isNoContent()).andReturn();
        String payload = jdbc.queryForObject("SELECT envelope FROM security_audit_event WHERE event_type='ALL_SESSIONS_REVOKED'", String.class);
        tools.jackson.databind.JsonNode envelope = tools.jackson.databind.json.JsonMapper.builder().build().readTree(payload);
        assertThat(envelope.path("schemaVersion").asInt()).isEqualTo(1);
        assertThat(envelope.path("eventType").asText()).isEqualTo("auth.logout.completed");
        assertThat(envelope.path("reasonCode").asText()).isEqualTo("LOGOUT_ALL");
        assertThat(envelope.path("actorType").asText()).isEqualTo("ACCOUNT");
        assertThat(envelope.path("actorId").asText()).isEqualTo(owner.accountId().toString());
        assertThat(envelope.path("sessionId").asText()).isEqualTo(first.sessionId().toString());
        assertThat(envelope.path("targetType").asText()).isEqualTo("ACCOUNT_GROUP");
        assertThat(envelope.path("targetId").asText()).isEqualTo(owner.accountGroupId().toString());
        assertThat(envelope.path("accountGroupId").asText()).isEqualTo(owner.accountGroupId().toString());
        assertThat(envelope.path("requestId").asText()).isEqualTo(action.getResponse().getHeader("X-Request-Id"));
        assertThat(payload).doesNotContain(email, PASSWORD, first.accessToken(), first.refreshToken(), rotated.refreshToken());
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM security_audit_event a JOIN outbox_event o ON o.id=a.id
                WHERE a.event_type='ALL_SESSIONS_REVOKED' AND o.aggregate_type='SECURITY_AUDIT'
                  AND o.aggregate_id=a.id AND o.aggregate_version=1 AND o.status='PENDING'
                  AND o.event_type='SECURITY_AUDIT_RECORDED' AND o.payload=a.envelope
                """, Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='SESSION_REVOKED' AND envelope IS NULL", Integer.class)).isEqualTo(2);


        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_session WHERE account_group_id=? AND status='ACTIVE'",
                Integer.class, bytes(owner.accountGroupId()))).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant WHERE revocation_reason='LOGOUT'", Integer.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_refresh_token WHERE revoked_at IS NOT NULL", Integer.class)).isEqualTo(3);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='SESSION_REVOKED'", Integer.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='ALL_SESSIONS_REVOKED'", Integer.class)).isEqualTo(1);
        for (TokenResponse device : List.of(first, second, rotated)) {
            assertThatThrownBy(() -> authentication.refresh(new RefreshRequest(device.refreshToken()))).isInstanceOf(AuthenticationFailure.class);
            mvc.perform(get("/api/v1/me").header("Authorization", "Bearer " + device.accessToken())).andExpect(status().isUnauthorized());
        }
        assertThat(authentication.me(stranger.sessionId(), other.accountId()).userId()).isEqualTo(other.userId());
        assertThat(authentication.refresh(new RefreshRequest(stranger.refreshToken())).sessionId()).isEqualTo(stranger.sessionId());
        assertThatThrownBy(() -> authentication.logoutAll(first.sessionId(), owner.accountId())).isInstanceOf(AuthenticationFailure.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='ALL_SESSIONS_REVOKED'", Integer.class)).isEqualTo(1);
    }

    @Test
    void liveLinkedGrantSustainsLogoutAllAfterOriginalGrantIsRevoked() {
        TokenResponse actor = login();
        TokenResponse device = login();
        UUID target = UUID.randomUUID();
        jdbc.update("""
            INSERT INTO user_account (id,user_id,type,display_name,status,created_at,updated_at)
            VALUES (?,?,'PERSONAL','Linked','ACTIVE',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))
            """, bytes(target), bytes(owner.userId()));
        jdbc.update("""
            INSERT INTO login_identity (id,account_id,type,identifier,password_hash,status,credential_version,created_at,updated_at)
            VALUES (?,?,'EMAIL',?,?,'ACTIVE',1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))
            """, bytes(UUID.randomUUID()), bytes(target), UUID.randomUUID()+"@example.com", passwords.encode(PASSWORD));
        jdbc.update("""
            INSERT INTO account_group_member (account_id,account_group_id,status,link_method,linked_by_account_id,linked_at)
            VALUES (?,?,'LINKED','REGISTRATION',?,UTC_TIMESTAMP(6))
            """, bytes(target), bytes(owner.accountGroupId()), bytes(owner.accountId()));
        com.unidocs.auth.account.application.LinkedAccountService.ChallengeResponse challenge = linked.challenge(
                actor.sessionId(), owner.accountId(), target, new com.unidocs.auth.account.api.ChallengeRequest(
                    com.unidocs.auth.account.domain.AccountChallenge.Purpose.UNLOCK,
                    com.unidocs.auth.account.domain.AccountChallenge.Method.PASSWORD));
        linked.complete(actor.sessionId(), owner.accountId(), target, challenge.id(),
                new com.unidocs.auth.account.api.AccountProofRequest(PASSWORD, null));
        jdbc.update("UPDATE session_account_grant SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6),revocation_reason='LOGOUT' WHERE session_id=? AND account_id=?",
                bytes(actor.sessionId()), bytes(owner.accountId()));

        authentication.logoutAll(actor.sessionId(), owner.accountId());

        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant WHERE status='ACTIVE'", Integer.class)).isZero();
        assertThatThrownBy(() -> authentication.me(device.sessionId(), owner.accountId())).isInstanceOf(AuthenticationFailure.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='ALL_SESSIONS_REVOKED'", Integer.class)).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"revoked", "expired", "grant_expired", "wrong_subject"})
    void invalidCallerCannotRevokeOtherDevices(String invalid) {
        TokenResponse actor = login();
        TokenResponse untouched = login();
        UUID subject = owner.accountId();
        if (invalid.equals("revoked")) authentication.logout(actor.sessionId(), subject);
        if (invalid.equals("expired")) jdbc.update("UPDATE user_session SET expires_at=authenticated_at-INTERVAL 3599 SECOND, authenticated_at=authenticated_at-INTERVAL 1 HOUR WHERE id=?", bytes(actor.sessionId()));
        if (invalid.equals("grant_expired")) jdbc.update("UPDATE session_account_grant SET idle_expires_at=authenticated_at WHERE session_id=?", bytes(actor.sessionId()));
        if (invalid.equals("wrong_subject")) subject = UUID.randomUUID();
        UUID suppliedSubject = subject;
        assertThatThrownBy(() -> authentication.logoutAll(actor.sessionId(), suppliedSubject)).isInstanceOf(AuthenticationFailure.class);
        assertThat(authentication.me(untouched.sessionId(), owner.accountId()).userId()).isEqualTo(owner.userId());
        assertThat(authentication.refresh(new RefreshRequest(untouched.refreshToken())).sessionId()).isEqualTo(untouched.sessionId());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='ALL_SESSIONS_REVOKED'", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE aggregate_type='SECURITY_AUDIT' AND JSON_UNQUOTE(JSON_EXTRACT(payload,'$.reasonCode'))='LOGOUT_ALL'", Integer.class)).isZero();
    }

    @Test
    void concurrentRefreshCannotEscapeAllDeviceRevocation() throws Exception {
        TokenResponse actor = login();
        TokenResponse device = login();
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<?> logout = executor.submit(() -> {
                start.await();
                authentication.logoutAll(actor.sessionId(), owner.accountId());
                return null;
            });
            Future<TokenResponse> refresh = executor.submit(() -> {
                start.await();
                try { return authentication.refresh(new RefreshRequest(device.refreshToken())); }
                catch (AuthenticationFailure failure) { return null; }
            });
            start.countDown();
            logout.get(15, TimeUnit.SECONDS);
            TokenResponse replacement = refresh.get(15, TimeUnit.SECONDS);
            if (replacement != null) {
                assertThatThrownBy(() -> authentication.refresh(new RefreshRequest(replacement.refreshToken()))).isInstanceOf(AuthenticationFailure.class);
            }
        }
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_session WHERE status='ACTIVE'", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant WHERE status='ACTIVE'", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_refresh_token WHERE revoked_at IS NULL", Integer.class)).isZero();
    }

    @ParameterizedTest
    @ValueSource(strings = {"INSERT INTO security_audit_event(id", "INSERT INTO outbox_event"})
    void actionAuditFailureRollsBackEveryDeviceGrantAndRefresh(String insert) {
        TokenResponse actor = login();
        TokenResponse device = login();
        authentication.refresh(new RefreshRequest(device.refreshToken()));
        int auditCount = jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event", Integer.class);
        int outboxCount = jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event", Integer.class);
        org.mockito.Mockito.doThrow(new org.springframework.dao.DataIntegrityViolationException("test-only"))
                .when(observedJdbc).update(org.mockito.ArgumentMatchers.startsWith(insert),
                        org.mockito.ArgumentMatchers.any(Object[].class));
        assertThatThrownBy(() -> authentication.logoutAll(actor.sessionId(), owner.accountId()))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_session WHERE status='ACTIVE'", Integer.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant WHERE status='ACTIVE'", Integer.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_refresh_token WHERE revoked_at IS NOT NULL", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event", Integer.class)).isEqualTo(auditCount);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event", Integer.class)).isEqualTo(outboxCount);
    }

    @Test
    void foreignAccountCannotProduceLogoutAllActionFacts() {
        TokenResponse actor = login();
        RegistrationCompletionResponse stranger = provision(UUID.randomUUID() + "@example.com");
        assertThatThrownBy(() -> authentication.logoutAll(actor.sessionId(), stranger.accountId()))
                .isInstanceOf(AuthenticationFailure.class);
        assertThat(authentication.me(actor.sessionId(), owner.accountId()).userId()).isEqualTo(owner.userId());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='ALL_SESSIONS_REVOKED'", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM outbox_event WHERE aggregate_type='SECURITY_AUDIT'
                  AND JSON_UNQUOTE(JSON_EXTRACT(payload,'$.reasonCode'))='LOGOUT_ALL'
                """, Integer.class)).isZero();
    }
}
