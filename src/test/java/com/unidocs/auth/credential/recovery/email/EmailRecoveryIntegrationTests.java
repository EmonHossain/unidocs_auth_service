package com.unidocs.auth.credential.recovery.email;

import java.util.UUID;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.dao.DataIntegrityViolationException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.reset;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.*;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.registration.application.*;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.student.*;
import com.unidocs.auth.authentication.application.*;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.organization.application.*;
import com.unidocs.auth.organization.api.*;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.organization.employee.*;
import com.unidocs.auth.account.application.LinkedAccountService;
import com.unidocs.auth.account.api.*;
import com.unidocs.auth.account.domain.AccountChallenge.*;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Import(EmailRecoveryIntegrationTests.DeliveryConfiguration.class)
class EmailRecoveryIntegrationTests extends MySqlIntegrationTest {
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired StudentAdmissionService admissions;
    @Autowired EmployeeService employees;
    @Autowired LinkedAccountService accounts;
    @Autowired EmailPasswordRecoveryService recovery;
    @Autowired CapturingDelivery delivery;
    @Autowired MockMvc mvc;
    @Autowired JsonMapper json;
    @MockitoSpyBean JdbcTemplate observedJdbc;
    record Actor(UUID account,String email,TokenResponse token) { }
    Actor actor() {
        String email=UUID.randomUUID()+"@example.com";
        RegistrationResponse pending=registrations.register(new RegistrationRequest("Recovery person",email,"old-password-long"));
        String code=delivery.messages.get(pending.id()).code();
        registrations.verify(pending.id(),new VerificationRequest(code));
        RegistrationCompletionResponse completed=provisioning.complete(pending.id(),new RegistrationCompletionRequest(code));
        return new Actor(completed.accountId(),email,authentication.login(new LoginRequest(email,"old-password-long")));
    }
    UUID request(Actor actor) {
        recovery.forgot(new EmailRecoveryRequests.Forgot(actor.email(),actor.account()));
        return UUID.fromString(jdbc.queryForObject("SELECT BIN_TO_UUID(id) FROM email_password_recovery WHERE account_id=? AND status='PENDING'",String.class,bytes(actor.account())));
    }
    @Test void personalResetIsOneUseRevokesSessionRefreshAndDoesNotIssueNewSession() throws Exception {
        Actor actor=actor();UUID id=request(actor);String code=delivery.messages.get(id).code();
        assertThat(code).matches("[0-9]{6}");
        String hash=jdbc.queryForObject("SELECT code_hash FROM email_password_recovery WHERE id=?",String.class,bytes(id));
        assertThat(hash).startsWith("$2").isNotEqualTo(code);
        assertThat(jdbc.queryForObject("SELECT TIMESTAMPDIFF(SECOND,created_at,expires_at) FROM email_password_recovery WHERE id=?",Integer.class,bytes(id))).isEqualTo(300);
        mvc.perform(post("/api/v1/auth/reset-password").contentType(MediaType.APPLICATION_JSON)
                .content("{\"recoveryId\":\""+id+"\",\"code\":\""+code+"\",\"newPassword\":\"new-password-long\"}"))
                .andExpect(status().isNoContent()).andExpect(header().string("Cache-Control","no-store"));
        mvc.perform(get("/api/v1/me").header("Authorization","Bearer "+actor.token().accessToken())).andExpect(status().isUnauthorized());
        assertThatThrownBy(()->authentication.refresh(new RefreshRequest(actor.token().refreshToken()))).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(()->authentication.login(new LoginRequest(actor.email(),"old-password-long"))).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(()->recovery.reset(new EmailRecoveryRequests.Reset(id,code,"again-password-long"))).isInstanceOf(RegistrationException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_session",Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type='PASSWORD_RESET_COMPLETED'",Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT aggregate_type FROM outbox_event WHERE event_type='PASSWORD_RESET_COMPLETED'",String.class)).isEqualTo("LOGIN_IDENTITY");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event e JOIN login_identity i ON i.id=e.aggregate_id WHERE e.event_type='PASSWORD_RESET_COMPLETED' AND i.account_id=? AND e.aggregate_version=i.credential_version AND CAST(JSON_UNQUOTE(JSON_EXTRACT(e.payload,'$.aggregateVersion')) AS UNSIGNED)=i.credential_version",Integer.class,bytes(actor.account()))).isEqualTo(1);
        String audit=jdbc.queryForObject("SELECT envelope FROM security_audit_event WHERE event_type='PASSWORD_RESET_COMPLETED' AND envelope IS NOT NULL",String.class);
        JsonNode envelope=json.readTree(audit);
        assertThat(envelope.path("schemaVersion").asInt()).isEqualTo(1);
        assertThat(envelope.path("eventType").asText()).isEqualTo("auth.password.reset.completed");
        assertThat(envelope.path("outcome").asText()).isEqualTo("SUCCESS");
        assertThat(envelope.path("reasonCode").asText()).isEqualTo("EMAIL_RECOVERY_VERIFIED");
        assertThat(envelope.path("actorType").asText()).isEqualTo("UNKNOWN");
        assertThat(envelope.path("actorId").isNull()).isTrue();
        assertThat(envelope.path("targetType").asText()).isEqualTo("ACCOUNT");
        assertThat(envelope.path("targetId").asText()).isEqualTo(actor.account().toString());
        assertThat(envelope.path("sessionId").isNull()).isTrue();
        assertThat(audit).doesNotContain("new-password-long",code,actor.email(),id.toString(),actor.token().refreshToken(),actor.token().accessToken());
        String payload=jdbc.queryForObject("SELECT o.payload FROM outbox_event o JOIN security_audit_event a ON a.id=o.id WHERE a.event_type='PASSWORD_RESET_COMPLETED' AND o.aggregate_type='SECURITY_AUDIT' AND o.aggregate_id=a.id AND o.aggregate_version=1 AND o.status='PENDING' AND o.event_type='SECURITY_AUDIT_RECORDED'",String.class);
        assertThat(json.readTree(payload)).isEqualTo(envelope);
        assertThat(jdbc.queryForObject("SELECT BIN_TO_UUID(id) FROM security_audit_event WHERE event_type='PASSWORD_RESET_COMPLETED' AND envelope IS NOT NULL",String.class)).isEqualTo(envelope.path("eventId").asText());
        assertThat(authentication.login(new LoginRequest(actor.email(),"new-password-long"))).isNotNull();
    }
    @ParameterizedTest
    @ValueSource(strings={"INSERT INTO security_audit_event","INSERT INTO outbox_event"})
    void auditPersistenceFailureRollsBackPasswordChallengeAndRevocations(String insert) {
        Actor actor=actor();UUID id=request(actor);String code=delivery.messages.get(id).code();
        String passwordHash=jdbc.queryForObject("SELECT password_hash FROM login_identity WHERE account_id=?",String.class,bytes(actor.account()));
        String codeHash=jdbc.queryForObject("SELECT code_hash FROM email_password_recovery WHERE id=?",String.class,bytes(id));
        int auditCount=jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event",Integer.class);
        int outboxCount=jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event",Integer.class);
        doAnswer(invocation->{
            Object[] parameters=(Object[])invocation.getRawArguments()[1];
            String sql=invocation.getArgument(0,String.class);
            boolean resetAudit=insert.contains("security_audit_event")
                    ?java.util.Arrays.asList(parameters).contains("PASSWORD_RESET_COMPLETED")
                    :sql.contains("'SECURITY_AUDIT'")&&java.util.Arrays.stream(parameters).anyMatch(parameter->
                        parameter instanceof String payload&&payload.contains("\"eventType\":\"auth.password.reset.completed\""));
            if(resetAudit)throw new DataIntegrityViolationException("test-only");
            return invocation.callRealMethod();
        }).when(observedJdbc).update(startsWith(insert),any(Object[].class));
        try {
            assertThatThrownBy(()->recovery.reset(new EmailRecoveryRequests.Reset(id,code,"new-password-long"))).isInstanceOf(DataIntegrityViolationException.class);
        } finally { reset(observedJdbc); }
        assertThat(jdbc.queryForObject("SELECT password_hash FROM login_identity WHERE account_id=?",String.class,bytes(actor.account()))).isEqualTo(passwordHash);
        assertThat(jdbc.queryForObject("SELECT credential_version FROM login_identity WHERE account_id=?",Long.class,bytes(actor.account()))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT status FROM email_password_recovery WHERE id=?",String.class,bytes(id))).isEqualTo("PENDING");
        assertThat(jdbc.queryForObject("SELECT code_hash FROM email_password_recovery WHERE id=?",String.class,bytes(id))).isEqualTo(codeHash);
        assertThat(jdbc.queryForObject("SELECT completed_at FROM email_password_recovery WHERE id=?",java.sql.Timestamp.class,bytes(id))).isNull();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event",Integer.class)).isEqualTo(auditCount);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event",Integer.class)).isEqualTo(outboxCount);
        assertThat(jdbc.queryForObject("SELECT status FROM user_session WHERE id=?",String.class,bytes(actor.token().sessionId()))).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT status FROM session_account_grant WHERE session_id=? AND account_id=?",String.class,bytes(actor.token().sessionId()),bytes(actor.account()))).isEqualTo("ACTIVE");
        assertThat(authentication.refresh(new RefreshRequest(actor.token().refreshToken()))).isNotNull();
        recovery.reset(new EmailRecoveryRequests.Reset(id,code,"new-password-long"));
    }
    @Test void wrongAttemptsExpirySupersessionAndCooldownPersistWithoutPasswordChange() {
        Actor actor=actor();UUID first=request(actor);String firstCode=delivery.messages.get(first).code();
        recovery.forgot(new EmailRecoveryRequests.Forgot(actor.email(),actor.account()));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM email_password_recovery",Integer.class)).isEqualTo(1);
        String wrong=firstCode.equals("000000")?"111111":"000000";
        for(int i=0;i<5;i++)assertThatThrownBy(()->recovery.reset(new EmailRecoveryRequests.Reset(first,wrong,"new-password-long"))).isInstanceOf(RegistrationException.class);
        assertThat(jdbc.queryForObject("SELECT attempts FROM email_password_recovery WHERE id=?",Integer.class,bytes(first))).isEqualTo(5);
        assertThat(jdbc.queryForObject("SELECT code_hash FROM email_password_recovery WHERE id=?",String.class,bytes(first))).isEqualTo("CONSUMED");
        assertThat(jdbc.queryForObject("SELECT status FROM email_password_recovery WHERE id=?",String.class,bytes(first))).isEqualTo("FAILED");
        jdbc.update("UPDATE email_password_recovery SET created_at=DATE_SUB(created_at,INTERVAL 61 SECOND) WHERE id=?",bytes(first));
        UUID second=request(actor);
        jdbc.update("UPDATE email_password_recovery SET expires_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND) WHERE id=?",bytes(second));
        assertThatThrownBy(()->recovery.reset(new EmailRecoveryRequests.Reset(second,delivery.messages.get(second).code(),"new-password-long"))).isInstanceOf(RegistrationException.class);
        assertThat(jdbc.queryForObject("SELECT status FROM email_password_recovery WHERE id=?",String.class,bytes(second))).isEqualTo("EXPIRED");
        assertThat(jdbc.queryForObject("SELECT code_hash FROM email_password_recovery WHERE id=?",String.class,bytes(second))).isEqualTo("CONSUMED");
        assertThatThrownBy(()->recovery.reset(new EmailRecoveryRequests.Reset(UUID.randomUUID(),"000000","new-password-long"))).isInstanceOf(RegistrationException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='PASSWORD_RESET_COMPLETED'",Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type='PASSWORD_RESET_COMPLETED'",Integer.class)).isZero();
        assertThat(authentication.login(new LoginRequest(actor.email(),"old-password-long"))).isNotNull();
    }
    @Test void missingEmployeePendingAndDeliveryFailureHaveGenericResponse() throws Exception {
        Actor owner=actor();OrganizationResponse company=organizations.create(owner.token().sessionId(),owner.account(),new OrganizationRequest(owner.account(),UUID.randomUUID(),"Company","company-"+UUID.randomUUID(),Organization.Type.COMPANY));
        EmployeeRequests.Credentials employee=employees.create(owner.token().sessionId(),owner.account(),company.id(),new EmployeeRequests.Create(owner.account(),UUID.randomUUID(),"Employee"));
        for(UUID account:new UUID[]{null,employee.accountId()}) {
            mvc.perform(post("/api/v1/auth/forgot-password").contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"missing@example.com\""+(account==null?"":",\"accountId\":\""+account+"\"")+"}"))
                    .andExpect(status().isAccepted()).andExpect(content().string(""));
        }
        registrations.register(new RegistrationRequest("Unverified","pending@example.com","old-password-long"));
        recovery.forgot(new EmailRecoveryRequests.Forgot("pending@example.com",null));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM email_password_recovery",Integer.class)).isZero();
        delivery.fail=true;
        try { mvc.perform(post("/api/v1/auth/forgot-password").contentType(MediaType.APPLICATION_JSON).content("{\"email\":\""+owner.email()+"\"}"))
                    .andExpect(status().isAccepted()).andExpect(content().string("")); }
        finally { delivery.fail=false; }
    }
    @Test void universityResetRevokesTargetGrantWhileOtherLoginAccountRemainsUsableAndRestrictionsDenyRecovery() throws Exception {
        Actor owner=actor(),student=actor();
        OrganizationResponse university=organizations.create(owner.token().sessionId(),owner.account(),new OrganizationRequest(owner.account(),UUID.randomUUID(),"University","university-"+UUID.randomUUID(),Organization.Type.UNIVERSITY));
        admissions.domain(owner.token().sessionId(),owner.account(),university.id(),new StudentRequests.Domain(owner.account(),"students.example.edu"));
        String email=UUID.randomUUID()+"@students.example.edu";
        StudentRequests.View pending=admissions.apply(student.token().sessionId(),student.account(),university.id(),new StudentRequests.Apply(student.account(),email,"university-password-long"),null);
        StudentRequests.View approved=admissions.verify(student.token().sessionId(),student.account(),university.id(),pending.id(),new StudentRequests.Verify(student.account(),delivery.messages.get(pending.id()).code()));
        UUID account=approved.studentAccountId();
        TokenResponse universityToken=authentication.loginAccount(account,new AccountLoginRequest("university-password-long"));
        LinkedAccountService.ChallengeResponse unlock=accounts.challenge(student.token().sessionId(),student.account(),account,new ChallengeRequest(Purpose.UNLOCK,Method.PASSWORD));
        accounts.complete(student.token().sessionId(),student.account(),account,unlock.id(),new AccountProofRequest("university-password-long",null));
        recovery.forgot(new EmailRecoveryRequests.Forgot(email,account));
        UUID id=UUID.fromString(jdbc.queryForObject("SELECT BIN_TO_UUID(id) FROM email_password_recovery WHERE account_id=? AND status='PENDING'",String.class,bytes(account)));
        recovery.reset(new EmailRecoveryRequests.Reset(id,delivery.messages.get(id).code(),"new-university-password"));
        assertThatThrownBy(()->authentication.refresh(new RefreshRequest(universityToken.refreshToken()))).isInstanceOf(AuthenticationFailure.class);
        mvc.perform(get("/api/v1/me").header("Authorization","Bearer "+universityToken.accessToken())).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/me").header("Authorization","Bearer "+student.token().accessToken())).andExpect(status().isOk());
        assertThat(jdbc.queryForObject("SELECT status FROM session_account_grant WHERE session_id=? AND account_id=?",String.class,bytes(student.token().sessionId()),bytes(account))).isEqualTo("REVOKED");
        jdbc.update("UPDATE organization_membership SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6),revoked_by=?,version=version+1,updated_at=UTC_TIMESTAMP(6) WHERE account_id=?",bytes(owner.account()),bytes(account));
        jdbc.update("UPDATE email_password_recovery SET created_at=DATE_SUB(created_at,INTERVAL 61 SECOND) WHERE account_id=?",bytes(account));
        recovery.forgot(new EmailRecoveryRequests.Forgot(email,account));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM email_password_recovery WHERE account_id=?",Integer.class,bytes(account))).isEqualTo(1);
    }
    @Test void replacementSupersedesPendingProofAndHourlyLimitIsDurable() {
        Actor actor=actor();UUID first=request(actor);String original=delivery.messages.get(first).code();
        jdbc.update("UPDATE email_password_recovery SET created_at=DATE_SUB(created_at,INTERVAL 61 SECOND) WHERE id=?",bytes(first));
        UUID second=request(actor);
        assertThat(jdbc.queryForObject("SELECT status FROM email_password_recovery WHERE id=?",String.class,bytes(first))).isEqualTo("SUPERSEDED");
        assertThat(jdbc.queryForObject("SELECT code_hash FROM email_password_recovery WHERE id=?",String.class,bytes(first))).isEqualTo("CONSUMED");
        assertThatThrownBy(()->recovery.reset(new EmailRecoveryRequests.Reset(first,original,"new-password-long"))).isInstanceOf(RegistrationException.class);
        assertThat(second).isNotEqualTo(first);
        for(int i=0;i<3;i++) {
            jdbc.update("UPDATE email_password_recovery SET created_at=DATE_SUB(created_at,INTERVAL 61 SECOND) WHERE account_id=?",bytes(actor.account()));
            request(actor);
        }
        jdbc.update("UPDATE email_password_recovery SET created_at=DATE_SUB(created_at,INTERVAL 61 SECOND) WHERE account_id=?",bytes(actor.account()));
        recovery.forgot(new EmailRecoveryRequests.Forgot(actor.email(),actor.account()));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM email_password_recovery WHERE account_id=?",Integer.class,bytes(actor.account()))).isEqualTo(5);
    }
    @Test void concurrentCorrectProofCanChangeCredentialOnlyOnce() throws Exception {
        Actor actor=actor();UUID id=request(actor);String code=delivery.messages.get(id).code();
        java.util.concurrent.ExecutorService executor=java.util.concurrent.Executors.newFixedThreadPool(2);
        java.util.concurrent.CountDownLatch ready=new java.util.concurrent.CountDownLatch(2);
        java.util.concurrent.CountDownLatch start=new java.util.concurrent.CountDownLatch(1);
        java.util.List<java.util.concurrent.Future<Boolean>> attempts=new java.util.ArrayList<>();
        try {
            for(int i=0;i<2;i++) {
                attempts.add(executor.submit(()->{
                    ready.countDown();start.await();
                    try { recovery.reset(new EmailRecoveryRequests.Reset(id,code,"new-password-long"));return true; }
                    catch(RegistrationException failure) { return false; }
                }));
            }
            assertThat(ready.await(10,java.util.concurrent.TimeUnit.SECONDS)).isTrue();start.countDown();
            int succeeded=0;
            for(java.util.concurrent.Future<Boolean> attempt:attempts)if(attempt.get(30,java.util.concurrent.TimeUnit.SECONDS))succeeded++;
            assertThat(succeeded).isEqualTo(1);
            assertThat(jdbc.queryForObject("SELECT credential_version FROM login_identity WHERE account_id=?",Long.class,bytes(actor.account()))).isEqualTo(2);
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type='PASSWORD_RESET_COMPLETED'",Integer.class)).isEqualTo(1);
        } finally { start.countDown();executor.shutdownNow(); }
    }
    @Test void concurrentWrongProofsCannotExceedAttemptLimitOrChangePassword() throws Exception {
        Actor actor=actor();UUID id=request(actor);String code=delivery.messages.get(id).code();
        String wrong=code.equals("000000")?"111111":"000000";
        java.util.concurrent.ExecutorService executor=java.util.concurrent.Executors.newFixedThreadPool(6);
        java.util.concurrent.CountDownLatch ready=new java.util.concurrent.CountDownLatch(6);
        java.util.concurrent.CountDownLatch start=new java.util.concurrent.CountDownLatch(1);
        java.util.List<java.util.concurrent.Future<Boolean>> attempts=new java.util.ArrayList<>();
        try {
            for(int i=0;i<6;i++) {
                attempts.add(executor.submit(()->{
                    ready.countDown();start.await();
                    try { recovery.reset(new EmailRecoveryRequests.Reset(id,wrong,"new-password-long"));return true; }
                    catch(RegistrationException failure) { return false; }
                }));
            }
            assertThat(ready.await(10,java.util.concurrent.TimeUnit.SECONDS)).isTrue();start.countDown();
            for(java.util.concurrent.Future<Boolean> attempt:attempts)assertThat(attempt.get(60,java.util.concurrent.TimeUnit.SECONDS)).isFalse();
            assertThat(jdbc.queryForObject("SELECT attempts FROM email_password_recovery WHERE id=?",Integer.class,bytes(id))).isEqualTo(5);
            assertThat(jdbc.queryForObject("SELECT status FROM email_password_recovery WHERE id=?",String.class,bytes(id))).isEqualTo("FAILED");
            assertThat(jdbc.queryForObject("SELECT code_hash FROM email_password_recovery WHERE id=?",String.class,bytes(id))).isEqualTo("CONSUMED");
            assertThat(jdbc.queryForObject("SELECT credential_version FROM login_identity WHERE account_id=?",Long.class,bytes(actor.account()))).isEqualTo(1);
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type='PASSWORD_RESET_COMPLETED'",Integer.class)).isZero();
            assertThat(authentication.login(new LoginRequest(actor.email(),"old-password-long"))).isNotNull();
        } finally { start.countDown();executor.shutdownNow(); }
    }
    record Delivered(String code,Instant expiry) { @Override public String toString(){ return "Delivered[REDACTED]"; } }
    static class CapturingDelivery implements VerificationDelivery,EmailRecoveryDelivery {
        final Map<UUID,Delivered> messages=new ConcurrentHashMap<>();boolean fail;
        @Override public void deliver(String email,UUID id,String code,Instant expiry) {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            if(fail)throw new IllegalStateException("delivery-secret");messages.put(id,new Delivered(code,expiry));
        }
    }
    @TestConfiguration(proxyBeanMethods=false)
    static class DeliveryConfiguration { @Bean CapturingDelivery capturingRecoveryDelivery() { return new CapturingDelivery(); } }
}
