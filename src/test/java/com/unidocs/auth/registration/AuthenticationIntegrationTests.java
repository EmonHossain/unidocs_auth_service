package com.unidocs.auth.registration;

import java.util.*;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.*;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;

import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.*;
import com.unidocs.auth.authentication.application.AuthenticationService.AccountPage;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.api.RegistrationCompletionResponse;
import com.unidocs.auth.registration.api.RegistrationResponse;
import com.unidocs.auth.registration.application.*;
import com.unidocs.auth.security.jwt.AccessTokens;
import com.unidocs.auth.session.domain.RefreshSecret;
import com.unidocs.auth.session.persistence.SessionRepository.Account;

import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
@org.junit.jupiter.api.extension.ExtendWith(OutputCaptureExtension.class)
class AuthenticationIntegrationTests extends MySqlIntegrationTest {
    private static final String PASSWORD = "test-password-long";
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired com.unidocs.auth.security.bruteforce.LoginAttackProtection loginProtection;
    @Autowired JwtDecoder decoder;
    @Autowired com.unidocs.auth.session.persistence.SessionRepository sessions;
    @Autowired org.springframework.security.crypto.password.PasswordEncoder passwords;
    @Autowired java.time.Clock clock;
    @Autowired org.springframework.transaction.PlatformTransactionManager transactionManager;
    @Autowired io.micrometer.core.instrument.MeterRegistry metrics;
    @Autowired com.unidocs.auth.session.application.SessionAccess access;
    @Autowired MockMvc mvc;
    @MockitoSpyBean AccessTokens tokens;
    @MockitoSpyBean org.springframework.jdbc.core.JdbcTemplate observedJdbc;
    String email;
    RegistrationCompletionResponse identity;

    @BeforeEach
    void provision() {
        email = UUID.randomUUID() + "@example.com";
        RegistrationResponse pending = registrations.register(new RegistrationRequest("Test User", email, PASSWORD));
        String proof = delivery.tokens.get(pending.id());
        registrations.verify(pending.id(), new VerificationRequest(proof));
        identity = provisioning.complete(pending.id(), new RegistrationCompletionRequest(proof));
    }

    TokenResponse login() { return authentication.login(new LoginRequest(email, PASSWORD)); }
    int count(String table) { return jdbc.queryForObject("SELECT COUNT(*) FROM " + table, Integer.class); }

    @Test
    void loginCreatesDurableInitialGrantAndMinimalJwtAndSanitizedResponses(CapturedOutput output) throws Exception {
        TokenResponse response = authentication.login(new LoginRequest(email.toUpperCase(Locale.ROOT), PASSWORD));
        Jwt jwt = decoder.decode(response.accessToken());
        assertThat(jwt.getClaims()).containsOnlyKeys("sub", "sid", "iss", "aud", "iat", "exp");
        assertThat(jwt.getSubject()).isEqualTo(identity.accountId().toString());
        assertThat(jwt.getClaimAsString("sid")).isEqualTo(response.sessionId().toString());
        assertThat(response.expiresIn()).isEqualTo(300);
        assertThat(count("user_session")).isEqualTo(1);
        assertThat(count("session_account_grant")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT CONCAT(status, ':', auth_method, ':', credential_version) FROM session_account_grant", String.class))
                .isEqualTo("ACTIVE:LOGIN:1");
        assertThat(jdbc.queryForObject("SELECT secret_hash FROM session_refresh_token", String.class))
                .isEqualTo(RefreshSecret.parse(response.refreshToken()).hash()).doesNotContain(response.refreshToken());
        mvc.perform(get("/api/v1/me").header("Authorization", "Bearer " + response.accessToken()))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.userId").value(identity.userId().toString()))
                .andExpect(jsonPath("$.preferredAccountId").value(identity.accountId().toString()));
        mvc.perform(get("/api/v1/me/accounts").header("Authorization", "Bearer " + response.accessToken()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.accounts[0].unlocked").value(true));
        mvc.perform(get("/.well-known/jwks.json")).andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value("test-key"))
                .andExpect(jsonPath("$.keys[0].d").doesNotExist());
        String auditPayload = jdbc.queryForObject("SELECT envelope FROM security_audit_event WHERE event_type='LOGIN_SUCCEEDED'", String.class);
        assertThat(auditPayload).contains("auth.login.succeeded").doesNotContain(email, PASSWORD, response.accessToken(), response.refreshToken());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE aggregate_type='SECURITY_AUDIT'", Integer.class)).isEqualTo(1);
        assertThat(output).doesNotContain(response.accessToken(), response.refreshToken(), PASSWORD);
        assertThat(response.toString()).doesNotContain(response.accessToken(), response.refreshToken());
    }

    @Test
    void replacingApplicationServiceKeepsDurableSessionAndRefreshState() {
        TokenResponse response = login();
        AuthenticationService restarted = new AuthenticationService(sessions, passwords, tokens, clock, transactionManager, metrics, access, loginProtection);
        assertThat(restarted.me(response.sessionId(), identity.accountId()).userId()).isEqualTo(identity.userId());
        TokenResponse replacement = restarted.refresh(new RefreshRequest(response.refreshToken()));
        AuthenticationService another = new AuthenticationService(sessions, passwords, tokens, clock, transactionManager, metrics, access, loginProtection);
        assertThatThrownBy(() -> another.refresh(new RefreshRequest(response.refreshToken()))).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(() -> restarted.refresh(new RefreshRequest(replacement.refreshToken()))).isInstanceOf(AuthenticationFailure.class);
    }

    @Test
    void loginAndRefreshHttpReturnNoStoreAndInvalidBearerIsSanitized() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(300)).andExpect(jsonPath("$.accessToken").isString());
        TokenResponse response = login();
        mvc.perform(post("/api/v1/auth/refresh").contentType("application/json")
                .content("{\"refreshToken\":\"" + response.refreshToken() + "\"}"))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.sessionId").value(response.sessionId().toString()));
        mvc.perform(get("/api/v1/me").header("Authorization", "Bearer invalid-sensitive-token"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.requestId").exists())
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("invalid-sensitive-token"))));
    }

    @Test
    void refreshRotatesAndProvenReplayCommitsFamilyRevocation() throws Exception {
        TokenResponse original = login();
        TokenResponse rotated = authentication.refresh(new RefreshRequest(original.refreshToken()));
        assertThat(rotated.refreshToken()).isNotEqualTo(original.refreshToken());
        assertThat(rotated.sessionId()).isEqualTo(original.sessionId());
        assertThat(count("session_refresh_token")).isEqualTo(2);
        RefreshSecret wrongConsumed = new RefreshSecret(RefreshSecret.parse(original.refreshToken()).id(), RefreshSecret.create().secret());
        assertThatThrownBy(() -> authentication.refresh(new RefreshRequest(wrongConsumed.value())))
                .isInstanceOf(AuthenticationFailure.class);
        assertThat(jdbc.queryForObject("SELECT status FROM user_session", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='REFRESH_REPLAY'", Integer.class)).isZero();

        org.springframework.test.web.servlet.MvcResult replay = mvc.perform(post("/api/v1/auth/refresh")
                        .contentType("application/json")
                        .content("{\"refreshToken\":\"" + original.refreshToken() + "\"}"))
                .andExpect(status().isUnauthorized()).andReturn();
        String auditPayload = jdbc.queryForObject("SELECT envelope FROM security_audit_event WHERE event_type='REFRESH_REPLAY'", String.class);
        tools.jackson.databind.JsonNode envelope = tools.jackson.databind.json.JsonMapper.builder().build().readTree(auditPayload);
        assertThat(envelope.path("schemaVersion").asInt()).isEqualTo(1);
        assertThat(envelope.path("eventType").asText()).isEqualTo("auth.token.refresh.failed");
        assertThat(envelope.path("reasonCode").asText()).isEqualTo("REFRESH_REPLAY");
        assertThat(envelope.path("actorType").asText()).isEqualTo("UNKNOWN");
        assertThat(envelope.path("actorId").isNull()).isTrue();
        assertThat(envelope.path("targetId").asText()).isEqualTo(original.sessionId().toString());
        assertThat(envelope.path("requestId").asText()).isEqualTo(replay.getResponse().getHeader("X-Request-Id"));
        assertThat(auditPayload).doesNotContain(email, PASSWORD, original.refreshToken(), rotated.refreshToken(), original.accessToken());
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM security_audit_event a JOIN outbox_event o ON o.id=a.id
                WHERE a.event_type='REFRESH_REPLAY' AND o.aggregate_type='SECURITY_AUDIT'
                  AND o.aggregate_id=a.id AND o.aggregate_version=1 AND o.status='PENDING'
                  AND o.event_type='SECURITY_AUDIT_RECORDED' AND o.payload=a.envelope
                """, Integer.class)).isEqualTo(1);

        assertThat(jdbc.queryForObject("SELECT status FROM user_session", String.class)).isEqualTo("REVOKED");
        assertThat(jdbc.queryForObject("SELECT revocation_reason FROM session_account_grant", String.class)).isEqualTo("REFRESH_REPLAY");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_refresh_token WHERE revoked_at IS NOT NULL", Integer.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='REFRESH_FAILED'", Integer.class)).isEqualTo(1);
        assertThatThrownBy(() -> authentication.refresh(new RefreshRequest(rotated.refreshToken()))).isInstanceOf(AuthenticationFailure.class);
        mvc.perform(get("/api/v1/me").header("Authorization", "Bearer " + rotated.accessToken())).andExpect(status().isUnauthorized());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type = 'REFRESH_REPLAY'", Integer.class)).isEqualTo(1);
    }

    @Test
    void wrongRefreshSecretDoesNotRevokeAndUnknownMalformedCredentialsFail() throws Exception {
        TokenResponse response = login();
        RefreshSecret wrong = new RefreshSecret(RefreshSecret.parse(response.refreshToken()).id(), RefreshSecret.create().secret());
        for (String value : List.of(wrong.value(), RefreshSecret.create().value(), "malformed")) {
            mvc.perform(post("/api/v1/auth/refresh").contentType("application/json")
                    .content("{\"refreshToken\":\"" + value + "\"}"))
                    .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.requestId").exists());
        }
        assertThat(jdbc.queryForObject("SELECT status FROM user_session", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='REFRESH_REPLAY'", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE aggregate_type='SECURITY_AUDIT' AND JSON_UNQUOTE(JSON_EXTRACT(payload,'$.reasonCode'))='REFRESH_REPLAY'", Integer.class)).isZero();
        assertGenericRefreshFailures(3, response);
        assertThat(authentication.refresh(new RefreshRequest(response.refreshToken())).sessionId()).isEqualTo(response.sessionId());
        assertGenericRefreshFailures(3, response);
    }

    @Test
    void logoutIsIdempotentAndInvalidatesAccessAndRefresh() throws Exception {
        TokenResponse response = login();
        for (int i = 0; i < 2; i++) {
            mvc.perform(post("/api/v1/auth/logout").header("Authorization", "Bearer " + response.accessToken()))
                    .andExpect(status().isNoContent());
        }
        mvc.perform(get("/api/v1/me/accounts").header("Authorization", "Bearer " + response.accessToken())).andExpect(status().isUnauthorized());
        assertThatThrownBy(() -> authentication.refresh(new RefreshRequest(response.refreshToken()))).isInstanceOf(AuthenticationFailure.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type = 'SESSION_REVOKED'", Integer.class)).isEqualTo(1);
        String payload = jdbc.queryForObject("""
                SELECT envelope FROM security_audit_event WHERE event_type='SESSION_REVOKED'
                """, String.class);
        tools.jackson.databind.JsonNode envelope = tools.jackson.databind.json.JsonMapper.builder().build().readTree(payload);
        assertThat(envelope.path("eventType").asText()).isEqualTo("auth.logout.completed");
        assertThat(envelope.path("actorId").asText()).isEqualTo(identity.accountId().toString());
        assertThat(envelope.path("targetId").asText()).isEqualTo(response.sessionId().toString());
        assertThat(envelope.path("reasonCode").asText()).isEqualTo("LOGOUT");
        assertThat(payload).doesNotContain(email, PASSWORD, response.accessToken(), response.refreshToken());
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM security_audit_event a JOIN outbox_event o ON o.id=a.id
                WHERE a.event_type='SESSION_REVOKED' AND o.aggregate_type='SECURITY_AUDIT'
                    AND o.aggregate_id=a.id AND o.aggregate_version=1
                    AND o.event_type='SECURITY_AUDIT_RECORDED' AND o.payload=a.envelope
                """, Integer.class)).isEqualTo(1);
    }

    @Test
    void logoutAuditOutboxFailureRollsBackSessionGrantAndRefreshRevocation() {
        TokenResponse response = login();
        int auditCount = count("security_audit_event");
        int outboxCount = count("outbox_event");
        doThrow(new org.springframework.dao.DataIntegrityViolationException("test-only")).when(observedJdbc)
                .update(startsWith("INSERT INTO outbox_event"), any(Object[].class));
        assertThatThrownBy(() -> authentication.logout(response.sessionId(), identity.accountId()))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThat(jdbc.queryForObject("SELECT status FROM user_session", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT status FROM session_account_grant", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_refresh_token WHERE revoked_at IS NOT NULL", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='SESSION_REVOKED'", Integer.class)).isZero();
        assertThat(count("security_audit_event")).isEqualTo(auditCount);
        assertThat(count("outbox_event")).isEqualTo(outboxCount);
    }

    @Test
    void logoutRejectsWrongSubjectWithoutWritingLogoutAudit() {
        TokenResponse response = login();
        assertThatThrownBy(() -> authentication.logout(response.sessionId(), UUID.randomUUID()))
                .isInstanceOf(AuthenticationFailure.class);
        assertThat(jdbc.queryForObject("SELECT status FROM user_session", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='SESSION_REVOKED'", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM outbox_event WHERE aggregate_type='SECURITY_AUDIT'
                    AND JSON_UNQUOTE(JSON_EXTRACT(payload,'$.eventType'))='auth.logout.completed'
                """, Integer.class)).isZero();
    }

    @Test
    void unknownAndWrongPasswordsAndUnverifiedRegistrationCannotLogin() throws Exception {
        String pendingEmail = "pending@example.com";
        registrations.register(new RegistrationRequest("Pending", pendingEmail, PASSWORD));
        for (String value : List.of(email, "unknown@example.com", pendingEmail)) {
            mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                    .content("{\"email\":\"" + value + "\",\"password\":\"wrong-secret\"}"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("wrong-secret"))));
        }
        assertThat(count("user_session")).isZero();
        assertThat(count("session_account_grant")).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type = 'LOGIN_FAILED'", Integer.class)).isEqualTo(3);
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM security_audit_event a JOIN outbox_event o ON o.id=a.id
                WHERE a.event_type='LOGIN_FAILED' AND o.aggregate_type='SECURITY_AUDIT'
                    AND JSON_UNQUOTE(JSON_EXTRACT(a.envelope,'$.actorType'))='UNKNOWN'
                """, Integer.class)).isEqualTo(3);
        assertThat(jdbc.queryForList("SELECT payload FROM outbox_event WHERE aggregate_type='SECURITY_AUDIT'", String.class))
                .allSatisfy(payload -> assertThat(payload).doesNotContain(email, pendingEmail, "unknown@example.com", "wrong-secret", PASSWORD));
        mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                .content("{\"email\":\"invalid\",\"password\":\"sensitive\"}"))
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "UPDATE users SET status = 'DISABLED'",
        "UPDATE user_account SET status = 'DISABLED'",
        "UPDATE login_identity SET status = 'DISABLED'",
        "UPDATE account_group SET status = 'DISABLED'",
        "UPDATE account_group_member SET status = 'DISCONNECTED'",
        "UPDATE login_identity SET credential_version = credential_version + 1",
        "UPDATE session_account_grant SET idle_expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND",
        "UPDATE session_account_grant SET idle_expires_at = authenticated_at, absolute_expires_at = authenticated_at + INTERVAL 1 SECOND",
        "UPDATE user_session SET expires_at = authenticated_at + INTERVAL 1 SECOND",
        "UPDATE session_refresh_token SET expires_at = created_at + INTERVAL 1 SECOND"
    })
    void mutableSecurityStateFailsClosed(String mutation) throws Exception {
        TokenResponse response = login();
        // Ensure one-second absolute-expiry mutations are in the past without sleeping.
        if (mutation.contains("+ INTERVAL 1 SECOND")) {
            jdbc.update("UPDATE user_session SET authenticated_at = authenticated_at - INTERVAL 1 HOUR");
            jdbc.update("UPDATE session_account_grant SET authenticated_at = authenticated_at - INTERVAL 1 HOUR");
            jdbc.update("UPDATE session_refresh_token SET created_at = created_at - INTERVAL 1 HOUR");
        }
        jdbc.update(mutation);
        assertThatThrownBy(() -> authentication.refresh(new RefreshRequest(response.refreshToken()))).isInstanceOf(AuthenticationFailure.class);
        assertGenericRefreshFailures(1, response);
        if (!mutation.contains("session_refresh_token")) {
            mvc.perform(get("/api/v1/me").header("Authorization", "Bearer " + response.accessToken())).andExpect(status().isUnauthorized());
        }
        if (mutation.contains("DISABLED") || mutation.contains("DISCONNECTED")) {
            assertThatThrownBy(this::login).isInstanceOf(AuthenticationFailure.class);
        }
    }

    @Test
    void signingFailureRollsBackLoginAndRefresh() {
        doThrow(new IllegalStateException("Signing unavailable")).when(tokens).issue(any(), any());
        assertThatThrownBy(this::login).isInstanceOf(IllegalStateException.class);
        assertThat(count("user_session")).isZero();
        assertThat(count("session_account_grant")).isZero();
        assertThat(count("session_refresh_token")).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type = 'LOGIN_SUCCEEDED'", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE aggregate_type='SECURITY_AUDIT'", Integer.class)).isZero();
        reset(tokens);
        TokenResponse response = login();
        doThrow(new IllegalStateException("Signing unavailable")).when(tokens).issue(any(), any());
        assertThatThrownBy(() -> authentication.refresh(new RefreshRequest(response.refreshToken()))).isInstanceOf(IllegalStateException.class);
        assertThat(count("session_refresh_token")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT used_at IS NULL FROM session_refresh_token", Boolean.class)).isTrue();
    }

    @Test
    void concurrentRefreshSerializesAndReplayRevokesWinningToken() throws Exception {
        TokenResponse response = login();
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Callable<Boolean> refresh = () -> {
                start.await();
                try { authentication.refresh(new RefreshRequest(response.refreshToken())); return true; }
                catch (AuthenticationFailure failure) { return false; }
            };
            Future<Boolean> first = executor.submit(refresh);
            Future<Boolean> second = executor.submit(refresh);
            start.countDown();
            assertThat(List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS))).containsExactlyInAnyOrder(true, false);
        }
        assertThat(count("session_refresh_token")).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT status FROM user_session", String.class)).isEqualTo("REVOKED");
    }

    @Test
    void concurrentLoginsHaveIndependentSessionsAndLogoutIsScoped() throws Exception {
        TokenResponse first;
        TokenResponse second;
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<TokenResponse> a = executor.submit(this::login);
            Future<TokenResponse> b = executor.submit(this::login);
            first = a.get(15, TimeUnit.SECONDS); second = b.get(15, TimeUnit.SECONDS);
        }
        assertThat(first.sessionId()).isNotEqualTo(second.sessionId());
        authentication.logout(first.sessionId(), identity.accountId());
        assertThat(authentication.me(second.sessionId(), identity.accountId()).userId()).isEqualTo(identity.userId());
        assertThatThrownBy(() -> authentication.me(first.sessionId(), identity.accountId())).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(() -> authentication.me(second.sessionId(), UUID.randomUUID())).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(() -> authentication.logout(second.sessionId(), UUID.randomUUID())).isInstanceOf(AuthenticationFailure.class);
    }

    @Test
    void accountsAreScopedPaginatedAndOtherLinkedAccountsRemainLocked() throws Exception {
        TokenResponse response = login();
        UUID extra = UUID.randomUUID();
        jdbc.update("""
            INSERT INTO user_account (id, user_id, type, display_name, status, created_at, updated_at)
            VALUES (?, ?, 'PERSONAL', 'Other linked account', 'ACTIVE', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
            """, bytes(extra), bytes(identity.userId()));
        jdbc.update("""
            INSERT INTO account_group_member (account_id, account_group_id, status, link_method, linked_by_account_id, linked_at)
            VALUES (?, ?, 'LINKED', 'REGISTRATION', ?, UTC_TIMESTAMP(6))
            """, bytes(extra), bytes(identity.accountGroupId()), bytes(identity.accountId()));
        jdbc.update("UPDATE user_preference SET preferred_account_id = ?", bytes(extra));
        RegistrationResponse strangerPending = registrations.register(new RegistrationRequest("Other human", "other-human@example.com", PASSWORD));
        String strangerProof = delivery.tokens.get(strangerPending.id());
        registrations.verify(strangerPending.id(), new VerificationRequest(strangerProof));
        RegistrationCompletionResponse stranger = provisioning.complete(strangerPending.id(), new RegistrationCompletionRequest(strangerProof));
        // Even an inconsistent cross-owner link must not expose another human's navigation data.
        jdbc.update("UPDATE account_group_member SET account_group_id = ? WHERE account_id = ?",
                bytes(identity.accountGroupId()), bytes(stranger.accountId()));
        AccountPage page = authentication.accounts(response.sessionId(), identity.accountId(), null, 1);
        assertThat(page.accounts()).hasSize(1);
        assertThat(page.nextCursor()).isNotNull();
        AccountPage next = authentication.accounts(response.sessionId(), identity.accountId(), page.nextCursor(), 1);
        assertThat(next.accounts()).hasSize(1);
        assertThat(next.nextCursor()).isNull();
        List<Account> both = authentication.accounts(response.sessionId(), identity.accountId(), null, 50).accounts();
        assertThat(both).hasSize(2).noneMatch(account -> account.id().equals(stranger.accountId()));
        assertThat(both).filteredOn(account -> account.id().equals(extra)).singleElement().extracting(account -> account.unlocked()).isEqualTo(false);
        assertThat(authentication.me(response.sessionId(), identity.accountId()).preferredAccountId()).isEqualTo(extra);
        assertThat(count("session_account_grant")).isEqualTo(1);
        mvc.perform(get("/api/v1/me/accounts?limit=101").header("Authorization", "Bearer " + response.accessToken())).andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @ValueSource(strings = {"INSERT INTO security_audit_event(id", "INSERT INTO outbox_event"})
    void genericRefreshAuditFailureRollsBackNoUsableAccountRevocation(String insert) {
        TokenResponse response = login();
        jdbc.update("UPDATE session_account_grant SET idle_expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND");
        int auditCount = count("security_audit_event");
        int outboxCount = count("outbox_event");
        doThrow(new org.springframework.dao.DataIntegrityViolationException("test-only")).when(observedJdbc)
                .update(startsWith(insert), any(Object[].class));
        assertThatThrownBy(() -> authentication.refresh(new RefreshRequest(response.refreshToken())))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThat(jdbc.queryForObject("SELECT status FROM user_session", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT status FROM session_account_grant", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT revoked_at IS NULL FROM session_refresh_token", Boolean.class)).isTrue();
        assertThat(count("security_audit_event")).isEqualTo(auditCount);
        assertThat(count("outbox_event")).isEqualTo(outboxCount);
    }

    private void assertGenericRefreshFailures(int expected, TokenResponse response) {
        List<String> payloads = jdbc.queryForList("SELECT envelope FROM security_audit_event WHERE event_type='REFRESH_FAILED'", String.class);
        assertThat(payloads).hasSize(expected).allSatisfy(payload -> {
            tools.jackson.databind.JsonNode envelope = tools.jackson.databind.json.JsonMapper.builder().build().readTree(payload);
            assertThat(envelope.path("eventType").asText()).isEqualTo("auth.token.refresh.failed");
            assertThat(envelope.path("reasonCode").asText()).isEqualTo("INVALID_REFRESH");
            assertThat(envelope.path("outcome").asText()).isEqualTo("FAILURE");
            assertThat(envelope.path("actorType").asText()).isEqualTo("UNKNOWN");
            assertThat(envelope.path("targetType").asText()).isEqualTo("AUTHENTICATION");
            for (String field : List.of("actorId", "targetId", "sessionId")) {
                assertThat(envelope.path(field).isNull()).as(field).isTrue();
            }
            assertThat(payload).doesNotContain(email, PASSWORD, response.refreshToken(), response.accessToken(), identity.accountId().toString());
        });
        assertThat(jdbc.queryForObject("""
                SELECT COUNT(*) FROM security_audit_event a JOIN outbox_event o ON o.id=a.id
                WHERE a.event_type='REFRESH_FAILED' AND a.user_id IS NULL AND a.account_id IS NULL
                  AND a.session_id IS NULL AND o.aggregate_type='SECURITY_AUDIT'
                  AND o.aggregate_id=a.id AND o.aggregate_version=1 AND o.status='PENDING'
                  AND o.event_type='SECURITY_AUDIT_RECORDED' AND o.payload=a.envelope
                """, Integer.class)).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"INSERT INTO security_audit_event(id", "INSERT INTO outbox_event"})
    void replayAuditPersistenceFailureRollsBackFamilyRevocation(String insert) {
        TokenResponse original = login();
        TokenResponse rotated = authentication.refresh(new RefreshRequest(original.refreshToken()));
        int auditCount = count("security_audit_event");
        int outboxCount = count("outbox_event");
        doThrow(new org.springframework.dao.DataIntegrityViolationException("test-only")).when(observedJdbc)
                .update(startsWith(insert), any(Object[].class));
        assertThatThrownBy(() -> authentication.refresh(new RefreshRequest(original.refreshToken())))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThat(jdbc.queryForObject("SELECT status FROM user_session", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT status FROM session_account_grant", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_refresh_token WHERE revoked_at IS NOT NULL", Integer.class)).isZero();
        assertThat(count("security_audit_event")).isEqualTo(auditCount);
        assertThat(count("outbox_event")).isEqualTo(outboxCount);
        assertThat(authentication.refresh(new RefreshRequest(rotated.refreshToken())).sessionId()).isEqualTo(original.sessionId());
    }
}

