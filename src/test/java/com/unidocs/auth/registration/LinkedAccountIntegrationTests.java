package com.unidocs.auth.registration;

import java.util.*;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.*;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;

import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.account.api.*;
import com.unidocs.auth.account.application.*;
import com.unidocs.auth.account.application.LinkedAccountService.ActionResponse;
import com.unidocs.auth.account.application.LinkedAccountService.ChallengeResponse;
import com.unidocs.auth.account.domain.AccountChallenge.*;
import com.unidocs.auth.account.domain.AccountChallenge.Purpose;
import com.unidocs.auth.account.persistence.AccountAccessRepository;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.*;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.api.RegistrationCompletionResponse;
import com.unidocs.auth.registration.api.RegistrationResponse;
import com.unidocs.auth.registration.application.*;

import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
@org.junit.jupiter.api.extension.ExtendWith(OutputCaptureExtension.class)
class LinkedAccountIntegrationTests extends MySqlIntegrationTest {
    static final String PASSWORD = "test-password-long";
    static final String OTHER_PASSWORD = "other-account-password";
    static final String PIN = "859271";
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired LinkedAccountService linked;
    @Autowired PasswordEncoder passwords;
    @Autowired MockMvc mvc;
    @Autowired org.springframework.transaction.PlatformTransactionManager transactionManager;
    @MockitoSpyBean AccountAccessRepository store;
    RegistrationCompletionResponse owner;
    TokenResponse session;
    String email;
    Map<UUID,String> accountEmails = new HashMap<>();

    @BeforeEach void createOwner() {
        email = UUID.randomUUID() + "@example.com";
        owner = provision(email);
        session = authentication.login(new LoginRequest(email, PASSWORD));
    }
    RegistrationCompletionResponse provision(String email) {
        RegistrationResponse pending = registrations.register(new RegistrationRequest("Human", email, PASSWORD));
        String proof = delivery.tokens.get(pending.id());
        registrations.verify(pending.id(), new VerificationRequest(proof));
        return provisioning.complete(pending.id(), new RegistrationCompletionRequest(proof));
    }
    UUID additional(boolean connected) {
        UUID id = UUID.randomUUID(); String email = UUID.randomUUID() + "@example.com";
        accountEmails.put(id,email);
        jdbc.update("""
            INSERT INTO user_account (id, user_id, type, display_name, status, created_at, updated_at)
            VALUES (?, ?, 'PERSONAL', 'Independent account', 'ACTIVE', UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
            """, bytes(id), bytes(owner.userId()));
        jdbc.update("""
            INSERT INTO login_identity (id, account_id, type, identifier, password_hash, status, credential_version, created_at, updated_at)
            VALUES (?, ?, 'EMAIL', ?, ?, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
            """, bytes(UUID.randomUUID()), bytes(id), email, passwords.encode(OTHER_PASSWORD));
        jdbc.update("""
            INSERT INTO account_group_member (account_id, account_group_id, status, link_method, linked_by_account_id, linked_at, disconnected_at)
            VALUES (?, ?, ?, 'REGISTRATION', ?, UTC_TIMESTAMP(6), ?)
            """, bytes(id), bytes(owner.accountGroupId()), connected ? "LINKED" : "DISCONNECTED", bytes(id),
                    connected ? null : java.sql.Timestamp.from(java.time.Instant.now()));
        return id;
    }
    LinkedAccountService.ChallengeResponse challenge(TokenResponse actor, UUID account, Purpose purpose, Method method) {
        return linked.challenge(actor.sessionId(), actor.loginAccountId(), account, new ChallengeRequest(purpose,method));
    }
    LinkedAccountService.ActionResponse prove(TokenResponse actor, UUID account, LinkedAccountService.ChallengeResponse challenge, String proof) {
        return linked.complete(actor.sessionId(),actor.loginAccountId(),account,challenge.id(),new AccountProofRequest(proof,null));
    }
    LinkedAccountService.ActionResponse unlock(TokenResponse actor, UUID account) {
        return prove(actor,account,challenge(actor,account,Purpose.UNLOCK,Method.PASSWORD),OTHER_PASSWORD);
    }
    void setPin(TokenResponse actor, UUID account, String password, String pin) {
        ChallengeResponse challenge = challenge(actor,account,Purpose.SET_PIN,Method.PASSWORD);
        linked.complete(actor.sessionId(),actor.loginAccountId(),account,challenge.id(),new AccountProofRequest(password,pin));
    }
    boolean unlocked(TokenResponse actor, UUID id) {
        return authentication.accounts(actor.sessionId(),actor.loginAccountId(),null,100).accounts().stream()
                .filter(account -> account.id().equals(id)).findFirst().orElseThrow().unlocked();
    }

    @Test void passwordUnlockPreservesInitialLoginGrantAndAllowsSimultaneousAccounts() {
        UUID target = additional(true);
        linked.preferred(session.sessionId(),session.loginAccountId(),target);
        assertThat(unlocked(session,target)).isFalse();
        ActionResponse result = unlock(session,target);
        assertThat(result.unlocked()).isTrue();
        assertThat(unlocked(session,owner.accountId())).isTrue();
        assertThat(unlocked(session,target)).isTrue();
        assertThat(jdbc.queryForList("SELECT auth_method FROM session_account_grant",String.class)).containsExactlyInAnyOrder("LOGIN","PASSWORD");
        assertThat(result.absoluteExpiresAt()).isBeforeOrEqualTo(jdbc.queryForObject("SELECT expires_at FROM user_session",java.sql.Timestamp.class).toInstant());
    }

    @Test void pinEnrollmentHashesAndPinUnlockUsesItsOwnCredentialVersion(CapturedOutput output) {
        UUID target = additional(true); unlock(session,target); setPin(session,target,OTHER_PASSWORD,PIN);
        String hash = jdbc.queryForObject("SELECT credential_hash FROM account_credential",String.class);
        assertThat(hash).isNotEqualTo(PIN); assertThat(passwords.matches(PIN,hash)).isTrue();
        ChallengeResponse proof = challenge(session,target,Purpose.UNLOCK,Method.PIN);
        assertThat(prove(session,target,proof,PIN).unlocked()).isTrue();
        jdbc.update("UPDATE login_identity SET credential_version = 2 WHERE account_id = ?",bytes(target));
        assertThat(unlocked(session,target)).isTrue();
        assertThat(jdbc.queryForObject("SELECT credential_source FROM session_account_grant WHERE account_id = ?",String.class,bytes(target)))
                .isEqualTo("ACCOUNT_CREDENTIAL");
        assertThat(output).doesNotContain(PIN,OTHER_PASSWORD,session.accessToken(),session.refreshToken());
        assertThat(new AccountProofRequest(PIN,PIN).toString()).doesNotContain(PIN);
    }

    @Test void pinChangesRevokeAllPinGrantsAndKeepPasswordProofGrants() {
        UUID target = additional(true); unlock(session,target); setPin(session,target,OTHER_PASSWORD,PIN);
        prove(session,target,challenge(session,target,Purpose.UNLOCK,Method.PIN),PIN);
        TokenResponse other = authentication.login(new LoginRequest(email,PASSWORD));
        prove(other,target,challenge(other,target,Purpose.UNLOCK,Method.PIN),PIN);
        setPin(session,target,OTHER_PASSWORD,"483912");
        assertThat(unlocked(other,target)).isFalse();
        assertThat(unlocked(session,target)).isTrue();
        assertThat(jdbc.queryForObject("SELECT version FROM account_credential",Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT revocation_reason FROM session_account_grant WHERE account_id = ? AND session_id = ?",
                String.class,bytes(target),bytes(other.sessionId()))).isEqualTo("CREDENTIAL_CHANGED");
    }

    @Test void pinFailuresLockCredentialAcrossFreshChallenges() {
        UUID target = additional(true); unlock(session,target); setPin(session,target,OTHER_PASSWORD,PIN);
        for (int i=0;i<5;i++) {
            ChallengeResponse proof = challenge(session,target,Purpose.UNLOCK,Method.PIN);
            assertThatThrownBy(() -> prove(session,target,proof,"111111")).isInstanceOf(AccountAccessDenied.class);
        }
        assertThat(jdbc.queryForObject("SELECT failed_attempts FROM account_credential",Integer.class)).isEqualTo(5);
        assertThat(jdbc.queryForObject("SELECT locked_until > UTC_TIMESTAMP(6) FROM account_credential",Boolean.class)).isTrue();
        assertThatThrownBy(() -> challenge(session,target,Purpose.UNLOCK,Method.PIN)).isInstanceOf(AccountAccessDenied.class);
        jdbc.update("UPDATE account_credential SET locked_until = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND");
        ChallengeResponse retry = challenge(session,target,Purpose.UNLOCK,Method.PIN);
        assertThat(prove(session,target,retry,PIN).unlocked()).isTrue();
        assertThat(jdbc.queryForObject("SELECT failed_attempts FROM account_credential",Integer.class)).isZero();
    }

    @Test void fiveWrongProofsConsumeAttemptBudgetAndNeverGrant() {
        UUID target = additional(true); ChallengeResponse proof = challenge(session,target,Purpose.UNLOCK,Method.PASSWORD);
        for (int i=0;i<5;i++) assertThatThrownBy(() -> prove(session,target,proof,"wrong-password")).isInstanceOf(AccountAccessDenied.class);
        assertThat(jdbc.queryForObject("SELECT attempts FROM account_challenge",Integer.class)).isEqualTo(5);
        assertThat(jdbc.queryForObject("SELECT status FROM account_challenge",String.class)).isEqualTo("FAILED");
        assertThatThrownBy(() -> prove(session,target,proof,OTHER_PASSWORD)).isInstanceOf(AccountAccessDenied.class);
        assertThat(unlocked(session,target)).isFalse();
    }

    @Test void challengesBindToSessionAccountPurposeAndRejectReplayAndExpiry() {
        UUID target = additional(true); ChallengeResponse proof = challenge(session,target,Purpose.UNLOCK,Method.PASSWORD);
        TokenResponse other = authentication.login(new LoginRequest(email,PASSWORD));
        assertThatThrownBy(() -> prove(other,target,proof,OTHER_PASSWORD)).isInstanceOf(AccountAccessDenied.class);
        assertThatThrownBy(() -> prove(session,owner.accountId(),proof,OTHER_PASSWORD)).isInstanceOf(AccountAccessDenied.class);
        assertThat(prove(session,target,proof,OTHER_PASSWORD).purpose()).isEqualTo(Purpose.UNLOCK);
        assertThatThrownBy(() -> prove(session,target,proof,OTHER_PASSWORD)).isInstanceOf(AccountAccessDenied.class);
        ChallengeResponse expired = challenge(session,target,Purpose.UNLOCK,Method.PASSWORD);
        jdbc.update("UPDATE account_challenge SET created_at = UTC_TIMESTAMP(6) - INTERVAL 3 MINUTE, expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 MINUTE WHERE id = ?",bytes(expired.id()));
        assertThatThrownBy(() -> prove(session,target,expired,OTHER_PASSWORD)).isInstanceOf(AccountAccessDenied.class);
        assertThat(jdbc.queryForObject("SELECT status FROM account_challenge WHERE id = ?",String.class,bytes(expired.id()))).isEqualTo("EXPIRED");
    }

    @Test void credentialChangesAfterChallengeRejectStaleProof() {
        UUID target = additional(true); ChallengeResponse proof = challenge(session,target,Purpose.UNLOCK,Method.PASSWORD);
        jdbc.update("UPDATE login_identity SET credential_version = credential_version + 1 WHERE account_id = ?",bytes(target));
        assertThatThrownBy(() -> prove(session,target,proof,OTHER_PASSWORD)).isInstanceOf(AccountAccessDenied.class);
        assertThat(unlocked(session,target)).isFalse();
    }

    @Test void ownedAccountLinkRequiresProofAndDoesNotUnlockOrChangePreference() {
        UUID target = additional(false);
        assertThatThrownBy(() -> challenge(session,target,Purpose.UNLOCK,Method.PASSWORD)).isInstanceOf(AccountAccessDenied.class);
        ChallengeResponse proof = challenge(session,target,Purpose.LINK,Method.PASSWORD);
        assertThatThrownBy(() -> prove(session,target,proof,"wrong-password")).isInstanceOf(AccountAccessDenied.class);
        assertThat(prove(session,target,proof,OTHER_PASSWORD).unlocked()).isFalse();
        assertThat(unlocked(session,target)).isFalse();
        assertThat(authentication.me(session.sessionId(),session.loginAccountId()).preferredAccountId()).isEqualTo(owner.accountId());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant",Integer.class)).isEqualTo(1);
    }

    @Test void otherHumanAndUnsupportedPasskeyCannotBeLinkedOrUnlocked() {
        RegistrationCompletionResponse stranger = provision("stranger@example.com");
        for (Purpose purpose : List.of(Purpose.LINK,Purpose.UNLOCK,Purpose.UNLINK,Purpose.SET_PIN)) {
            assertThatThrownBy(() -> challenge(session,stranger.accountId(),purpose,Method.PASSWORD)).isInstanceOf(AccountAccessDenied.class);
        }
        assertThatThrownBy(() -> challenge(session,owner.accountId(),Purpose.UNLOCK,Method.PASSKEY)).isInstanceOf(AccountAccessDenied.class);
        assertThatThrownBy(() -> linked.preferred(session.sessionId(),session.loginAccountId(),stranger.accountId())).isInstanceOf(AccountAccessDenied.class);
    }

    @Test void unlinkRevokesTargetAcrossSessionsAndCancelsChallenges() {
        UUID target = additional(true); unlock(session,target);
        TokenResponse other = authentication.login(new LoginRequest(email,PASSWORD)); unlock(other,target);
        linked.preferred(session.sessionId(),session.loginAccountId(),target);
        ChallengeResponse pending = challenge(other,target,Purpose.UNLOCK,Method.PASSWORD);
        ChallengeResponse proof = challenge(session,target,Purpose.UNLINK,Method.PASSWORD);
        ActionResponse result = prove(session,target,proof,OTHER_PASSWORD);
        assertThat(result.sessionRevoked()).isFalse(); assertThat(result.preferredAccountId()).isEqualTo(owner.accountId());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant WHERE account_id = ? AND status = 'ACTIVE'",Integer.class,bytes(target))).isZero();
        assertThat(authentication.accounts(other.sessionId(),other.loginAccountId(),null,100).accounts()).noneMatch(a -> a.id().equals(target));
        assertThatThrownBy(() -> prove(other,target,pending,OTHER_PASSWORD)).isInstanceOf(AccountAccessDenied.class);
        assertThat(authentication.refresh(new RefreshRequest(other.refreshToken())).sessionId()).isEqualTo(other.sessionId());
    }

    @Test void unlinkOriginalLoginAccountKeepsSurvivingGrantAndJwtSubject() {
        UUID target = additional(true); unlock(session,target);
        ActionResponse result = prove(session,owner.accountId(),challenge(session,owner.accountId(),Purpose.UNLINK,Method.PASSWORD),PASSWORD);
        assertThat(result.sessionRevoked()).isFalse(); assertThat(result.preferredAccountId()).isEqualTo(target);
        assertThat(authentication.me(session.sessionId(),session.loginAccountId()).userId()).isEqualTo(owner.userId());
        assertThat(authentication.refresh(new RefreshRequest(session.refreshToken())).loginAccountId()).isEqualTo(owner.accountId());
        assertThat(unlocked(session,target)).isTrue();
    }

    @Test void unlinkLastUsableGrantChoosesLockedFallbackAndTerminatesSessions() {
        UUID target = additional(true);
        TokenResponse other = authentication.login(new LoginRequest(email,PASSWORD));
        ActionResponse result = prove(session,owner.accountId(),challenge(session,owner.accountId(),Purpose.UNLINK,Method.PASSWORD),PASSWORD);
        assertThat(result.sessionRevoked()).isTrue(); assertThat(result.preferredAccountId()).isEqualTo(target);
        assertThatThrownBy(() -> authentication.refresh(new RefreshRequest(session.refreshToken()))).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(() -> authentication.me(other.sessionId(),other.loginAccountId())).isInstanceOf(AuthenticationFailure.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_session WHERE status = 'ACTIVE'",Integer.class)).isZero();
        TokenResponse fallbackLogin = authentication.login(new LoginRequest(accountEmails.get(target),OTHER_PASSWORD));
        assertThat(fallbackLogin.loginAccountId()).isEqualTo(target);
    }

    @Test void linkedGrantIdleAndAbsoluteExpiryDoNotKillUnrelatedGrants() {
        UUID target = additional(true); unlock(session,target);
        jdbc.update("UPDATE session_account_grant SET idle_expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND WHERE account_id = ?",bytes(target));
        assertThat(unlocked(session,target)).isFalse(); assertThat(unlocked(session,owner.accountId())).isTrue();
        unlock(session,target);
        jdbc.update("UPDATE session_account_grant SET authenticated_at = UTC_TIMESTAMP(6) - INTERVAL 1 HOUR, idle_expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND, absolute_expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND WHERE account_id = ?",bytes(target));
        assertThat(unlocked(session,target)).isFalse();
        assertThat(authentication.refresh(new RefreshRequest(session.refreshToken())).sessionId()).isEqualTo(session.sessionId());
    }

    @Test void policyVersionsFailClosedAndNewLoginUsesCurrentDurablePolicy() {
        UUID target = additional(true); ChallengeResponse proof = challenge(session,target,Purpose.UNLOCK,Method.PASSWORD);
        jdbc.update("UPDATE session_grant_policy SET version = 2, idle_timeout_seconds = 600, absolute_timeout_seconds = 3600");
        assertThatThrownBy(() -> prove(session,target,proof,OTHER_PASSWORD)).isInstanceOf(AuthenticationFailure.class);
        TokenResponse fresh = authentication.login(new LoginRequest(email,PASSWORD));
        assertThat(jdbc.queryForObject("SELECT policy_version FROM session_account_grant WHERE session_id = ?",Long.class,bytes(fresh.sessionId()))).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT TIMESTAMPDIFF(SECOND, authenticated_at, absolute_expires_at) FROM session_account_grant WHERE session_id = ?",Long.class,bytes(fresh.sessionId()))).isEqualTo(3600);
    }

    @Test void concurrentSameChallengeConsumesOnceAndLoginDoesNotDeadlock() throws Exception {
        UUID target = additional(true); ChallengeResponse proof = challenge(session,target,Purpose.UNLOCK,Method.PASSWORD);
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Callable<Boolean> verify = () -> { start.await(); try { prove(session,target,proof,OTHER_PASSWORD); return true; } catch (AccountAccessDenied denied) { return false; } };
            Future<Boolean> first = executor.submit(verify); Future<Boolean> second = executor.submit(verify);
            Future<TokenResponse> login = executor.submit(() -> { start.await(); return authentication.login(new LoginRequest(accountEmails.get(target),OTHER_PASSWORD)); });
            start.countDown();
            assertThat(List.of(first.get(20,TimeUnit.SECONDS),second.get(20,TimeUnit.SECONDS))).containsExactlyInAnyOrder(true,false);
            assertThat(login.get(20,TimeUnit.SECONDS).loginAccountId()).isEqualTo(target);
        }
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type = 'ACCOUNT_UNLOCKED'",Integer.class)).isEqualTo(1);
    }

    @Test void grantFailureRollsBackProofConsumptionAndAllowsRetry() {
        UUID target = additional(true); ChallengeResponse proof = challenge(session,target,Purpose.UNLOCK,Method.PASSWORD);
        doAnswer(invocation -> { invocation.callRealMethod(); throw new org.springframework.dao.DataAccessResourceFailureException("Persistence unavailable"); }).when(store).grant(any(),any(),any(),any());
        assertThatThrownBy(() -> prove(session,target,proof,OTHER_PASSWORD)).isInstanceOf(org.springframework.dao.DataAccessResourceFailureException.class);
        assertThat(jdbc.queryForObject("SELECT status FROM account_challenge",String.class)).isEqualTo("PENDING");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant",Integer.class)).isEqualTo(1);
        reset(store);
        assertThat(prove(session,target,proof,OTHER_PASSWORD).unlocked()).isTrue();
    }

    @Test void inheritedTransactionsAreRejectedBeforeProofWork() {
        UUID target = additional(true); ChallengeResponse proof = challenge(session,target,Purpose.UNLOCK,Method.PASSWORD);
        TransactionTemplate transaction = new org.springframework.transaction.support.TransactionTemplate(transactionManager);
        assertThatThrownBy(() -> transaction.execute(status -> prove(session,target,proof,OTHER_PASSWORD)))
                .isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
        assertThatThrownBy(() -> transaction.execute(status -> authentication.login(new LoginRequest(email,PASSWORD))))
                .isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
        assertThat(jdbc.queryForObject("SELECT status FROM account_challenge",String.class)).isEqualTo("PENDING");
    }

    @Test void concurrentUnlinkAndUnlockCannotLeaveValidTargetGrant() throws Exception {
        UUID target = additional(true);
        TokenResponse other = authentication.login(new LoginRequest(email,PASSWORD));
        ChallengeResponse unlockProof = challenge(other,target,Purpose.UNLOCK,Method.PASSWORD);
        ChallengeResponse unlinkProof = challenge(session,target,Purpose.UNLINK,Method.PASSWORD);
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> unlock = executor.submit(() -> {
                start.await();
                try { prove(other,target,unlockProof,OTHER_PASSWORD); return true; }
                catch (AccountAccessDenied denied) { return false; }
            });
            Future<ActionResponse> unlink = executor.submit(() -> { start.await(); return prove(session,target,unlinkProof,OTHER_PASSWORD); });
            start.countDown();
            unlock.get(20,TimeUnit.SECONDS);
            assertThat(unlink.get(20,TimeUnit.SECONDS).sessionRevoked()).isFalse();
        }
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant WHERE account_id = ? AND status = 'ACTIVE'",Integer.class,bytes(target))).isZero();
        assertThat(authentication.accounts(other.sessionId(),other.loginAccountId(),null,100).accounts()).noneMatch(a -> a.id().equals(target));
    }

    @Test void httpRequiresBearerAndRejectsBadInputWithNoSecretEcho() throws Exception {
        mvc.perform(post("/api/v1/accounts/"+owner.accountId()+"/challenges").contentType("application/json")
                .content("{\"purpose\":\"UNLOCK\",\"method\":\"PASSWORD\"}")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/accounts/"+owner.accountId()+"/challenges").header("Authorization","Bearer "+session.accessToken())
                .contentType("application/json").content("{\"purpose\":\"UNLOCK\",\"method\":\"PASSWORD\"}"))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control","no-store"));
        ChallengeResponse proof = challenge(session,owner.accountId(),Purpose.SET_PIN,Method.PASSWORD);
        mvc.perform(post("/api/v1/accounts/"+owner.accountId()+"/challenges/"+proof.id()+"/complete")
                .header("Authorization","Bearer "+session.accessToken()).contentType("application/json")
                .content("{\"secret\":\"sensitive-password\",\"newPin\":\"123\"}"))
                .andExpect(status().isBadRequest()).andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("sensitive-password"))));
        mvc.perform(put("/api/v1/me/preferred-account").header("Authorization","Bearer "+session.accessToken()).contentType("application/json")
                .content("{\"accountId\":\""+owner.accountId()+"\"}")).andExpect(status().isOk());
    }
    @Test void extraPreferenceFieldsNeverChangeIdentityOrAuthorizeLinkedAccount() throws Exception {
        UUID target=additional(true);
        mvc.perform(put("/api/v1/me/preferred-account").header("Authorization","Bearer "+session.accessToken())
                .contentType("application/json").content("{\"accountId\":\""+target+"\",\"userId\":\""+UUID.randomUUID()
                    +"\",\"role\":\"OWNER\",\"authorities\":[\"ROLE_ADMIN\"],\"unlocked\":true,\"credentialVersion\":999}"))
                .andExpect(status().isOk());
        assertThat(authentication.me(session.sessionId(),session.loginAccountId()).preferredAccountId()).isEqualTo(target);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant WHERE session_id=? AND account_id=? AND status='ACTIVE'",Integer.class,
                bytes(session.sessionId()),bytes(target))).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant WHERE session_id=? AND status='ACTIVE'",Integer.class,bytes(session.sessionId()))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT user_id FROM user_account WHERE id=?",byte[].class,bytes(target))).isEqualTo(bytes(owner.userId()));
        assertThat(jdbc.queryForObject("SELECT credential_version FROM login_identity WHERE account_id=?",Long.class,bytes(target))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM organization_membership",Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM group_membership",Integer.class)).isZero();
    }

}
