package com.unidocs.auth.registration;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.api.RegistrationCompletionResponse;
import com.unidocs.auth.registration.api.RegistrationResponse;
import com.unidocs.auth.registration.application.*;
import com.unidocs.auth.registration.domain.*;
import com.unidocs.auth.registration.persistence.CoreIdentityRepository;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
@ExtendWith(OutputCaptureExtension.class)
class RegistrationProvisioningIntegrationTests extends MySqlIntegrationTest {
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired MockMvc mvc;
    @Autowired PlatformTransactionManager transactionManager;
    @MockitoSpyBean CoreIdentityRepository identityWriter;

    private static final List<String> IDENTITY_TABLES = List.of("users", "user_profile", "user_contact", "user_preference",
            "user_account", "login_identity", "account_group", "account_group_member");

    private RegistrationResponse register(String email) {
        return registrations.register(new RegistrationRequest("Test User", email, "test-password-long"));
    }

    private RegistrationResponse verified(String email) {
        RegistrationResponse registration = register(email);
        return registrations.verify(registration.id(), new VerificationRequest(delivery.tokens.get(registration.id())));
    }

    private RegistrationCompletionRequest proof(UUID id) {
        return new RegistrationCompletionRequest(delivery.tokens.get(id));
    }

    private byte[] binary(UUID id) {
        return ByteBuffer.allocate(16).putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits()).array();
    }

    private void assertIdentityCounts(int expected) {
        for (String table : IDENTITY_TABLES) {
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM " + table, Integer.class)).as(table).isEqualTo(expected);
        }
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event", Integer.class)).isEqualTo(expected * 2);
    }

    @Test
    void completionCreatesWholeIdentityAndReturnsTheSameDurableResultOnRetry(CapturedOutput output) throws Exception {
        String email = UUID.randomUUID() + "@example.com";
        RegistrationResponse registration = verified(email);
        assertIdentityCounts(0);
        String originalHash = jdbc.queryForObject("SELECT password_hash FROM pending_registration WHERE id = ?",
                String.class, binary(registration.id()));
        RegistrationCompletionResponse first = provisioning.complete(registration.id(), proof(registration.id()));
        assertThat(first.status()).isEqualTo(RegistrationStatus.COMPLETED);
        assertThat(provisioning.complete(registration.id(), proof(registration.id()))).isEqualTo(first);
        mvc.perform(post("/api/v1/registrations/" + registration.id() + "/complete").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + proof(registration.id()).token() + "\"}"))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.status").value("COMPLETED"))
                .andExpect(jsonPath("$.userId").value(first.userId().toString()))
                .andExpect(jsonPath("$.accountId").value(first.accountId().toString()))
                .andExpect(jsonPath("$.accountGroupId").value(first.accountGroupId().toString()))
                .andExpect(jsonPath("$.token").doesNotExist()).andExpect(jsonPath("$.passwordHash").doesNotExist());
        assertIdentityCounts(1);
        assertThat(jdbc.queryForObject("SELECT password_hash FROM login_identity WHERE account_id = ?",
                String.class, binary(first.accountId()))).isEqualTo(originalHash);
        assertThat(jdbc.queryForObject("SELECT HEX(user_id) FROM user_account WHERE id = ?",
                String.class, binary(first.accountId()))).isEqualTo(java.util.HexFormat.of().withUpperCase().formatHex(binary(first.userId())));
        assertThat(jdbc.queryForObject("SELECT verified FROM user_contact WHERE user_id = ?", Boolean.class,
                binary(first.userId()))).isTrue();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_profile WHERE first_name IS NULL AND last_name IS NULL",
                Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT HEX(preferred_account_id) FROM user_preference WHERE user_id = ?",
                String.class, binary(first.userId()))).isEqualTo(java.util.HexFormat.of().withUpperCase().formatHex(binary(first.accountId())));
        assertThat(jdbc.queryForObject("SELECT CONCAT(theme, ':', time_zone, ':', email_notifications, ':', push_notifications, ':', security_notifications) FROM user_preference",
                String.class)).isEqualTo("SYSTEM:UTC:0:0:1");
        assertThat(jdbc.queryForObject("SELECT link_method FROM account_group_member WHERE account_id = ?",
                String.class, binary(first.accountId()))).isEqualTo("REGISTRATION");
        assertThat(jdbc.queryForList("SELECT event_type FROM security_audit_event", String.class))
                .containsExactlyInAnyOrder("REGISTRATION_COMPLETED", "ACCOUNT_LINKED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_session", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM organization_membership", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'workspace'",
                Integer.class)).isZero();
        mvc.perform(get("/api/v1/me").header("X-User-Id", first.userId().toString())).andExpect(status().isUnauthorized());
        assertThatThrownBy(() -> registrations.verify(registration.id(), new VerificationRequest(proof(registration.id()).token())))
                .isInstanceOf(RegistrationException.class);
        assertThat(output).doesNotContain(proof(registration.id()).token(), "test-password-long", originalHash);
    }

    @Test
    void pendingUnknownMalformedAndWrongProofRequestsCannotProvisionOrReadTheResult() throws Exception {
        RegistrationResponse pending = register(UUID.randomUUID() + "@example.com");
        assertBadRequest(pending.id(), proof(pending.id()));
        assertBadRequest(UUID.randomUUID(), new RegistrationCompletionRequest("wrong"));
        assertBadRequest(pending.id(), null);
        assertBadRequest(pending.id(), new RegistrationCompletionRequest(""));
        assertBadRequest(pending.id(), new RegistrationCompletionRequest("x".repeat(129)));
        mvc.perform(post("/api/v1/registrations/" + pending.id() + "/complete").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"\"}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.status").value(400));
        RegistrationResponse first = verified(UUID.randomUUID() + "@example.com");
        RegistrationResponse second = verified(UUID.randomUUID() + "@example.com");
        assertBadRequest(first.id(), proof(second.id()));
        assertIdentityCounts(0);
        provisioning.complete(first.id(), proof(first.id()));
        assertBadRequest(first.id(), new RegistrationCompletionRequest("wrong"));
        assertIdentityCounts(1);
    }

    @Test
    void verifiedProofCanCompleteAfterVerificationExpiryButNotAfterRegistrationDeadline() {
        RegistrationResponse registration = verified(UUID.randomUUID() + "@example.com");
        jdbc.update("UPDATE registration_verification SET expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND WHERE pending_registration_id = ?",
                binary(registration.id()));
        RegistrationCompletionResponse response = provisioning.complete(registration.id(), proof(registration.id()));
        assertThat(response.status()).isEqualTo(RegistrationStatus.COMPLETED);
        jdbc.update("UPDATE pending_registration SET expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND WHERE id = ?",
                binary(registration.id()));
        assertBadRequest(registration.id(), proof(registration.id()));
        RegistrationResponse expired = verified(UUID.randomUUID() + "@example.com");
        jdbc.update("UPDATE pending_registration SET expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND WHERE id = ?", binary(expired.id()));
        assertBadRequest(expired.id(), proof(expired.id()));
        assertIdentityCounts(1);
        assertThat(registrationStatus(expired.id())).isEqualTo("VERIFIED");
    }

    @Test
    void failedAndExpiredVerificationNeverProvisionEvenWithTheCorrectToken() {
        RegistrationResponse failed = register(UUID.randomUUID() + "@example.com");
        for (int attempt = 0; attempt < 5; attempt++) {
            assertThatThrownBy(() -> registrations.verify(failed.id(), new VerificationRequest("wrong")))
                    .isInstanceOf(RegistrationException.class);
        }
        assertBadRequest(failed.id(), proof(failed.id()));
        RegistrationResponse expired = register(UUID.randomUUID() + "@example.com");
        jdbc.update("UPDATE registration_verification SET expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND WHERE pending_registration_id = ?",
                binary(expired.id()));
        assertThatThrownBy(() -> registrations.verify(expired.id(), new VerificationRequest(proof(expired.id()).token())))
                .isInstanceOf(RegistrationException.class);
        assertBadRequest(expired.id(), proof(expired.id()));
        assertIdentityCounts(0);
    }

    @Test
    void duplicateNormalizedEmailReturnsConflictWithoutChangingTheExistingIdentity() throws Exception {
        RegistrationResponse first = verified("  Same@EXAMPLE.COM  ");
        RegistrationResponse duplicate = verified("same@example.com");
        assertThat(jdbc.queryForList("SELECT identifier FROM pending_registration", String.class))
                .containsExactlyInAnyOrder("same@example.com", "same@example.com");
        RegistrationCompletionResponse result = provisioning.complete(first.id(), proof(first.id()));
        mvc.perform(post("/api/v1/registrations/" + duplicate.id() + "/complete").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + proof(duplicate.id()).token() + "\"}"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.detail").value("The request could not be processed."));
        assertIdentityCounts(1);
        assertThat(registrationStatus(duplicate.id())).isEqualTo("VERIFIED");
        assertThat(provisioning.complete(first.id(), proof(first.id()))).isEqualTo(result);
    }

    @Test
    void injectedRolesAndAuthoritiesNeverProvisionPrivilegedMembershipsOrGrants() throws Exception {
        UUID suppliedOrganization = UUID.randomUUID();
        String injectedFields = "\"role\":\"ADMIN\",\"roles\":[\"OWNER\",\"ADMIN\"],"
                + "\"authorities\":[\"ROLE_ADMIN\"],\"organizationId\":\"" + suppliedOrganization
                + "\",\"accountType\":\"COMPANY\",\"registrationType\":\"COMPANY\"";
        UUID registrationId = registerWithInjectedFields(injectedFields);
        verifyAndCompleteWithInjectedFields(registrationId, injectedFields);
        assertTrustedProvisionedDefaults(registrationId);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM organization", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM organization_membership", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM group_membership", Integer.class)).isZero();
    }

    @Test
    void injectedInternalSecurityFieldsCannotControlPendingOrProvisionedState() throws Exception {
        UUID suppliedId = UUID.randomUUID();
        String injectedFields = "\"id\":\"" + suppliedId + "\",\"userId\":\"" + suppliedId
                + "\",\"accountId\":\"" + suppliedId + "\",\"accountGroupId\":\"" + suppliedId
                + "\",\"status\":\"COMPLETED\",\"verified\":true,\"enabled\":false,"
                + "\"locked\":true,\"accountNonLocked\":false,\"credentialVersion\":999,"
                + "\"passwordHash\":\"attacker-controlled-hash\",\"externalSubject\":\"attacker\","
                + "\"identityType\":\"ACCOUNT_ID\",\"expiresAt\":\"2999-01-01T00:00:00Z\","
                + "\"verifiedAt\":\"2000-01-01T00:00:00Z\",\"completedAt\":\"2000-01-01T00:00:00Z\"";
        UUID registrationId = registerWithInjectedFields(injectedFields);
        assertThat(registrationId).isNotEqualTo(suppliedId);
        verifyAndCompleteWithInjectedFields(registrationId, injectedFields);
        assertTrustedProvisionedDefaults(registrationId);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM users WHERE id = ?", Integer.class,
                binary(suppliedId))).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_account WHERE id = ?", Integer.class,
                binary(suppliedId))).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM account_group WHERE id = ?", Integer.class,
                binary(suppliedId))).isZero();
        assertThat(jdbc.queryForObject("SELECT password_hash FROM login_identity", String.class))
                .isNotEqualTo("attacker-controlled-hash");
        assertThat(jdbc.queryForObject("SELECT TIMESTAMPDIFF(SECOND, created_at, expires_at) FROM pending_registration WHERE id = ?",
                Integer.class, binary(registrationId))).isEqualTo(86_400);
    }

    private UUID registerWithInjectedFields(String fields) throws Exception {
        String email = UUID.randomUUID() + "@example.com";
        MvcResult result = mvc.perform(post("/api/v1/registrations")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"displayName\":\"User\",\"email\":\"" + email
                                + "\",\"password\":\"test-password-long\"," + fields + "}"))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.status").value("PENDING_VERIFICATION"))
                .andReturn();
        UUID id = UUID.fromString(result.getResponse().getHeader("Location")
                .replace("/api/v1/registrations/", ""));
        assertThat(registrationStatus(id)).isEqualTo("PENDING_VERIFICATION");
        assertThat(jdbc.queryForObject("SELECT CONCAT(registration_type, ':', identity_type) FROM pending_registration WHERE id = ?",
                String.class, binary(id))).isEqualTo("PERSONAL:EMAIL");
        assertThat(jdbc.queryForObject("SELECT verified_at FROM pending_registration WHERE id = ?",
                java.sql.Timestamp.class, binary(id))).isNull();
        assertThat(jdbc.queryForObject("SELECT completed_at FROM pending_registration WHERE id = ?",
                java.sql.Timestamp.class, binary(id))).isNull();
        assertIdentityCounts(0);
        return id;
    }

    private void verifyAndCompleteWithInjectedFields(UUID id, String fields) throws Exception {
        String request = "{\"token\":\"" + proof(id).token() + "\"," + fields + "}";
        mvc.perform(post("/api/v1/registrations/" + id + "/verify").contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("VERIFIED"));
        assertIdentityCounts(0);
        mvc.perform(post("/api/v1/registrations/" + id + "/complete").contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("COMPLETED"));
    }

    private void assertTrustedProvisionedDefaults(UUID registrationId) {
        assertIdentityCounts(1);
        assertThat(jdbc.queryForObject("SELECT status FROM users", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT CONCAT(type, ':', status) FROM user_account", String.class))
                .isEqualTo("PERSONAL:ACTIVE");
        assertThat(jdbc.queryForObject("SELECT CONCAT(type, ':', status, ':', credential_version) FROM login_identity",
                String.class)).isEqualTo("EMAIL:ACTIVE:1");
        assertThat(jdbc.queryForObject("SELECT external_subject FROM login_identity", String.class)).isNull();
        assertThat(jdbc.queryForObject("SELECT last_authenticated_at FROM login_identity", java.sql.Timestamp.class)).isNull();
        assertThat(jdbc.queryForObject("SELECT status FROM account_group", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT CONCAT(status, ':', link_method) FROM account_group_member", String.class))
                .isEqualTo("LINKED:REGISTRATION");
        assertThat(jdbc.queryForObject("SELECT verified FROM user_contact", Boolean.class)).isTrue();
        assertThat(jdbc.queryForObject("SELECT password_hash FROM login_identity", String.class))
                .isEqualTo(jdbc.queryForObject("SELECT password_hash FROM pending_registration WHERE id = ?",
                        String.class, binary(registrationId)));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_session", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM organization_membership", Integer.class)).isZero();
    }

    @Test
    void concurrentCompletionOfTheSameRegistrationReturnsOneIdentity() throws Exception {
        RegistrationResponse registration = verified(UUID.randomUUID() + "@example.com");
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Callable<RegistrationCompletionResponse> complete = () -> {
                start.await();
                return provisioning.complete(registration.id(), proof(registration.id()));
            };
            Future<RegistrationCompletionResponse> first = executor.submit(complete);
            Future<RegistrationCompletionResponse> second = executor.submit(complete);
            start.countDown();
            assertThat(first.get(15, TimeUnit.SECONDS)).isEqualTo(second.get(15, TimeUnit.SECONDS));
        }
        assertIdentityCounts(1);
    }

    @Test
    void concurrentDuplicateEmailsAreResolvedByTheDatabaseUniqueIndexWithoutPartialIdentityOrSecretLogs(CapturedOutput output) throws Exception {
        String email = UUID.randomUUID() + "@example.com";
        RegistrationResponse first = verified("  " + email.toUpperCase(java.util.Locale.ROOT) + "  ");
        RegistrationResponse second = verified(email);
        assertThat(jdbc.queryForList("SELECT identifier FROM pending_registration", String.class))
                .containsExactlyInAnyOrder(email, email);
        CyclicBarrier readyToPersist = new CyclicBarrier(2);
        doAnswer(invocation -> {
            readyToPersist.await(15, TimeUnit.SECONDS);
            return invocation.callRealMethod();
        }).when(identityWriter).persist(any(ProvisionedIdentity.class));
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<HttpStatus> one = executor.submit(() -> completionStatus(first));
            Future<HttpStatus> two = executor.submit(() -> completionStatus(second));
            assertThat(List.of(one.get(20, TimeUnit.SECONDS), two.get(20, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(HttpStatus.OK, HttpStatus.CONFLICT);
        }
        assertIdentityCounts(1);
        assertThat(List.of(registrationStatus(first.id()), registrationStatus(second.id())))
                .containsExactlyInAnyOrder("COMPLETED", "VERIFIED");
        assertThat(output).doesNotContain(email, proof(first.id()).token(), proof(second.id()).token(), "test-password-long");
    }

    @Test
    void aFailureAfterInsertsRollsBackAllIdentityAndAuditRowsThenRetriesWithoutReverification() {
        RegistrationResponse registration = verified(UUID.randomUUID() + "@example.com");
        AtomicBoolean failOnce = new AtomicBoolean(true);
        doAnswer(invocation -> {
            invocation.callRealMethod();
            if (failOnce.getAndSet(false)) { throw new IllegalStateException("Injected provisioning failure."); }
            return null;
        }).when(identityWriter).persist(any(ProvisionedIdentity.class));
        assertThatThrownBy(() -> provisioning.complete(registration.id(), proof(registration.id())))
                .isInstanceOf(org.springframework.dao.InvalidDataAccessApiUsageException.class)
                .hasRootCauseInstanceOf(IllegalStateException.class);
        assertIdentityCounts(0);
        assertThat(registrationStatus(registration.id())).isEqualTo("VERIFIED");
        assertThat(jdbc.queryForObject("SELECT completed_at FROM pending_registration WHERE id = ?",
                java.sql.Timestamp.class, binary(registration.id()))).isNull();
        assertThat(provisioning.complete(registration.id(), proof(registration.id())).status()).isEqualTo(RegistrationStatus.COMPLETED);
        assertIdentityCounts(1);
    }

    @Test
    void completionRejectsOuterTransactionsAndCrossOwnerPreferencesAndDuplicateLinks() {
        RegistrationResponse first = verified(UUID.randomUUID() + "@example.com");
        TransactionTemplate transactions = new TransactionTemplate(transactionManager);
        assertThatThrownBy(() -> transactions.execute(status -> provisioning.complete(first.id(), proof(first.id()))))
                .isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
        assertIdentityCounts(0);
        RegistrationCompletionResponse a = provisioning.complete(first.id(), proof(first.id()));
        RegistrationResponse second = verified(UUID.randomUUID() + "@example.com");
        RegistrationCompletionResponse b = provisioning.complete(second.id(), proof(second.id()));
        assertThatThrownBy(() -> jdbc.update("UPDATE user_preference SET preferred_account_id = ? WHERE user_id = ?",
                binary(b.accountId()), binary(a.userId()))).isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> jdbc.update("INSERT INTO account_group_member (account_id, account_group_id, status, link_method, linked_by_account_id, linked_at) VALUES (?, ?, 'LINKED', 'REGISTRATION', ?, UTC_TIMESTAMP(6))",
                binary(a.accountId()), binary(b.accountGroupId()), binary(a.accountId())))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertIdentityCounts(2);
    }

    private void assertBadRequest(UUID id, RegistrationCompletionRequest request) {
        assertThatThrownBy(() -> provisioning.complete(id, request)).isInstanceOfSatisfying(RegistrationException.class,
                exception -> assertThat(exception.status()).isEqualTo(HttpStatus.BAD_REQUEST));
    }

    private String registrationStatus(UUID id) {
        return jdbc.queryForObject("SELECT status FROM pending_registration WHERE id = ?", String.class, binary(id));
    }

    private HttpStatus completionStatus(RegistrationResponse registration) {
        try {
            provisioning.complete(registration.id(), proof(registration.id()));
            return HttpStatus.OK;
        } catch (RegistrationException exception) { return exception.status(); }
    }
}
