package com.unidocs.auth.registration;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.*;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.*;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import com.unidocs.auth.RedisIntegrationTest;
import com.unidocs.auth.account.lifecycle.*;
import com.unidocs.auth.account.lifecycle.AccountLifecycleService.Result;
import com.unidocs.auth.account.api.*;
import com.unidocs.auth.account.application.LinkedAccountService;
import com.unidocs.auth.account.domain.AccountChallenge.*;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.authentication.application.*;
import com.unidocs.auth.organization.api.*;
import com.unidocs.auth.organization.application.*;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.application.*;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties="auth.authorization.cache.enabled=true")
@AutoConfigureMockMvc
@Import({RegistrationIntegrationTests.DeliveryConfiguration.class,InvitationIntegrationTests.DeliveryConfiguration.class,
        AccountLifecycleIntegrationTests.NoticeConfiguration.class})
class AccountLifecycleIntegrationTests extends RedisIntegrationTest {
    static final String PASSWORD="test-password-long";
    static final String ORG_PASSWORD="independent-org-password";
    @Autowired org.springframework.context.ApplicationContext application;
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery registrationMail;
    @Autowired InvitationIntegrationTests.CapturingInvitations invitationMail;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired InvitationService invitations;
    @Autowired OrganizationAccountService orgAccounts;
    @Autowired LinkedAccountService linked;
    @Autowired AccountLifecycleService lifecycle;
    @Autowired AccountNoticeDispatcher dispatcher;
    @Autowired CapturingNotices notices;
    @Autowired MockMvc mvc;
    @Autowired com.unidocs.auth.group.application.GroupService groups;
    @Autowired com.unidocs.auth.group.application.GroupMembershipService groupMemberships;
    @Autowired com.unidocs.auth.group.application.GroupJoinService groupJoins;
    @Autowired org.springframework.transaction.PlatformTransactionManager transactions;
    @MockitoSpyBean OutboxRepository outbox;
    @MockitoSpyBean com.unidocs.auth.authorization.application.OrganizationSnapshotCache snapshots;
    record Actor(RegistrationCompletionResponse identity,TokenResponse token,String email) { }
    record Fixture(Actor owner,Actor human,OrganizationResponse org,OrganizationAccountResponse account,TokenResponse orgToken) { }
    @BeforeEach void setupNotices() { notices.fail=false;notices.enabled=true;notices.sent.clear();invitationMail.fail=false;registrationMail.fail=false; }
    Actor actor() {
        String email=UUID.randomUUID()+"@example.com";
        RegistrationResponse registration=registrations.register(new RegistrationRequest("Human",email,PASSWORD));
        String proof=registrationMail.tokens.get(registration.id());registrations.verify(registration.id(),new VerificationRequest(proof));
        RegistrationCompletionResponse identity=provisioning.complete(registration.id(),new RegistrationCompletionRequest(proof));
        return new Actor(identity,authentication.login(new LoginRequest(email,PASSWORD)),email);
    }
    Fixture fixture() {
        Actor owner=actor();Actor human=actor();
        OrganizationResponse org=organizations.create(owner.token().sessionId(),owner.identity().accountId(),new OrganizationRequest(owner.identity().accountId(),UUID.randomUUID(),"Org","org-"+UUID.randomUUID(),Organization.Type.UNIVERSITY));
        com.unidocs.auth.registration.student.StudentRequests.View admitted=StudentFixture.admit(application,human.token(),org.id(),ORG_PASSWORD);
        OrganizationAccountResponse account=new OrganizationAccountResponse(admitted.studentAccountId(),org.id(),admitted.membershipId(),com.unidocs.auth.account.domain.UserAccount.Type.UNIVERSITY,"Student");
        return new Fixture(owner,human,org,account,authentication.loginAccount(account.accountId(),new AccountLoginRequest(ORG_PASSWORD)));
    }
    Result remove(Actor actor,UUID account) { return lifecycle.remove(actor.token().sessionId(),actor.identity().accountId(),new LifecycleRequests.Remove(account,UUID.randomUUID(),PASSWORD)); }
    Result action(Fixture f,LifecycleRequests.Action action,Instant until) {
        return lifecycle.adminAction(f.owner().token().sessionId(),f.owner().identity().accountId(),f.org().id(),f.account().membershipId(),
                new LifecycleRequests.AdminAction(f.owner().identity().accountId(),action,until,"Administrator security decision",PASSWORD));
    }
    String accountStatus(UUID account) { return jdbc.queryForObject("SELECT status FROM user_account WHERE id=?",String.class,bytes(account)); }
    com.unidocs.auth.group.api.GroupMembershipResponse assignGroup(Fixture fixture,UUID account) {
        com.unidocs.auth.group.api.GroupResponse group=groups.create(fixture.owner().token().sessionId(),fixture.owner().identity().accountId(),fixture.org().id(),
                new com.unidocs.auth.group.api.GroupRequest(fixture.owner().identity().accountId(),UUID.randomUUID(),"Lifecycle group",com.unidocs.auth.group.domain.Group.Type.TEAM,null));
        return groupMemberships.assign(fixture.owner().token().sessionId(),fixture.owner().identity().accountId(),fixture.org().id(),group.id(),
                new com.unidocs.auth.group.api.GroupAssignmentRequest(fixture.owner().identity().accountId(),UUID.randomUUID(),account,"retained-role",
                    Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MICROS),null));
    }
    int count(String table) { return jdbc.queryForObject("SELECT COUNT(*) FROM "+table,Integer.class); }
    com.unidocs.auth.group.api.GroupJoinResponse submitGroupJoin(Fixture fixture,UUID account,TokenResponse token) {
        com.unidocs.auth.group.api.GroupResponse group=groups.create(fixture.owner().token().sessionId(),fixture.owner().identity().accountId(),fixture.org().id(),
                new com.unidocs.auth.group.api.GroupRequest(fixture.owner().identity().accountId(),UUID.randomUUID(),"Retention join group",com.unidocs.auth.group.domain.Group.Type.CLASS,null));
        return groupJoins.submit(token.sessionId(),token.loginAccountId(),fixture.org().id(),group.id(),
                new com.unidocs.auth.group.api.GroupJoinRequests.Submit(account,UUID.randomUUID(),"retained-student","Retained private request reason"));
    }
    void unlock(TokenResponse token,UUID account,String password) {
        LinkedAccountService.ChallengeResponse challenge=linked.challenge(token.sessionId(),token.loginAccountId(),account,new ChallengeRequest(Purpose.UNLOCK,Method.PASSWORD));
        linked.complete(token.sessionId(),token.loginAccountId(),account,challenge.id(),new AccountProofRequest(password,null));
    }
    @Test void personalRemovalRetainsDataRevokesSessionsAndRecoversWithoutOldGrants() {
        Actor actor=actor();Result removed=remove(actor,actor.identity().accountId());
        assertThat(removed.status()).isEqualTo("SOFT_DELETED");assertThat(removed.retainUntil()).isAfter(Instant.now());
        assertThat(count("login_identity")).isEqualTo(1);assertThat(count("user_contact")).isEqualTo(1);
        assertThatThrownBy(()->authentication.me(actor.token().sessionId(),actor.identity().accountId())).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(()->authentication.login(new LoginRequest(actor.email(),PASSWORD))).isInstanceOf(AuthenticationFailure.class);
        Result restored=lifecycle.restorePersonal(actor.identity().accountId(),new LifecycleRequests.Restore(PASSWORD));
        assertThat(restored.status()).isEqualTo("ACTIVE");
        assertThatThrownBy(()->authentication.refresh(new RefreshRequest(actor.token().refreshToken()))).isInstanceOf(AuthenticationFailure.class);
        assertThat(authentication.login(new LoginRequest(actor.email(),PASSWORD)).loginAccountId()).isEqualTo(actor.identity().accountId());
        dispatcher.dispatch();assertThat(notices.sent).hasSize(2);
    }
    @Test void multipleAccountsRequireSelectionAndCannotDeleteSomeoneElsesAccount() {
        Fixture f=fixture();
        assertThat(lifecycle.options(f.human().token().sessionId(),f.human().identity().accountId(),null,50).selectionRequired()).isTrue();
        assertThatThrownBy(()->remove(f.human(),null)).isInstanceOf(LifecycleFailure.class).hasMessage("ACCOUNT_SELECTION_REQUIRED");
        assertThatThrownBy(()->remove(f.human(),f.owner().identity().accountId())).isInstanceOf(LifecycleFailure.class);
        assertThat(accountStatus(f.human().identity().accountId())).isEqualTo("ACTIVE");
    }
    @Test void personalDeletionKeepsUmbrellaSessionIfAnotherRootHasCurrentGrant() {
        Fixture f=fixture();unlock(f.human().token(),f.account().accountId(),ORG_PASSWORD);
        remove(f.human(),f.human().identity().accountId());
        assertThat(authentication.me(f.human().token().sessionId(),f.human().identity().accountId()).preferredAccountId()).isEqualTo(f.account().accountId());
        assertThat(organizations.get(f.human().token().sessionId(),f.human().identity().accountId(),f.account().accountId(),f.org().id()).id()).isEqualTo(f.org().id());
        assertThat(authentication.refresh(new RefreshRequest(f.human().token().refreshToken())).loginAccountId()).isEqualTo(f.human().identity().accountId());
    }
    @Test void noticesFailClosedWhenDeliveryIsNotConfigured() {
        Actor actor=actor();notices.enabled=false;
        assertThatThrownBy(()->remove(actor,actor.identity().accountId())).isInstanceOf(LifecycleFailure.class).hasMessage("SECURITY_NOTICE_DELIVERY_UNAVAILABLE");
        assertThat(accountStatus(actor.identity().accountId())).isEqualTo("ACTIVE");assertThat(count("account_security_notice")).isZero();
    }
    @Test void passwordFailuresCommitAttemptLimitAndNeverRemoveAccount() {
        Actor actor=actor();for(int i=0;i<5;i++) assertThatThrownBy(()->lifecycle.remove(actor.token().sessionId(),actor.identity().accountId(),
                new LifecycleRequests.Remove(actor.identity().accountId(),UUID.randomUUID(),"wrong-password"))).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(()->remove(actor,actor.identity().accountId())).isInstanceOf(AuthenticationFailure.class);
        assertThat(jdbc.queryForObject("SELECT lifecycle_attempts FROM login_identity WHERE account_id=?",Integer.class,bytes(actor.identity().accountId()))).isEqualTo(5);
        assertThat(accountStatus(actor.identity().accountId())).isEqualTo("ACTIVE");
    }
    @Test void purgeErasesPersonalCredentialsAndProfileAndIsIdempotent() {
        Actor actor=actor();remove(actor,actor.identity().accountId());
        jdbc.update("UPDATE user_account SET retain_until=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND WHERE id=?",bytes(actor.identity().accountId()));
        assertThatThrownBy(()->lifecycle.restorePersonal(actor.identity().accountId(),new LifecycleRequests.Restore(PASSWORD))).isInstanceOf(AuthenticationFailure.class);
        lifecycle.maintain();lifecycle.maintain();assertThat(accountStatus(actor.identity().accountId())).isEqualTo("PURGED");
        for(String table:List.of("login_identity","user_contact","user_profile","user_preference","pending_registration","registration_verification","account_security_notice")) assertThat(count(table)).isZero();
        assertThat(jdbc.queryForList("SELECT secret_hash FROM session_refresh_token",String.class)).allMatch(hash->hash.equals("0".repeat(64)));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type='ACCOUNT_PURGED'",Integer.class)).isEqualTo(1);
    }
    @Test void mailFailureRetriesDurableNoticeWithoutDatabaseTransaction() {
        Actor actor=actor();remove(actor,actor.identity().accountId());notices.fail=true;dispatcher.dispatch();
        assertThat(jdbc.queryForObject("SELECT attempts FROM account_security_notice",Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT status FROM account_security_notice",String.class)).isEqualTo("PENDING");
        notices.fail=false;jdbc.update("UPDATE account_security_notice SET available_at=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND");dispatcher.dispatch();
        assertThat(notices.sent).hasSize(1);assertThat(jdbc.queryForObject("SELECT status FROM account_security_notice",String.class)).isEqualTo("SENT");
    }
    @Test void noticeDispatcherRejectsAmbientTransactionsBeforeDelivery() {
        org.springframework.transaction.support.TransactionTemplate transaction=new org.springframework.transaction.support.TransactionTemplate(transactions);
        assertThatThrownBy(()->transaction.execute(status->{dispatcher.dispatch();return true;})).isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
        assertThat(notices.sent).isEmpty();
    }
    @Test void apiSelectionAuthenticationAndRecoveryAreExplicit() throws Exception {
        Fixture f=fixture();String body="{\"requestId\":\""+UUID.randomUUID()+"\",\"password\":\""+PASSWORD+"\"}";
        mvc.perform(post("/api/v1/me/account-removals").contentType("application/json").content(body)).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/me/account-removals").header("Authorization","Bearer "+f.human().token().accessToken()).contentType("application/json").content(body))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("ACCOUNT_SELECTION_REQUIRED")).andExpect(jsonPath("$.selectionUrl").exists());
        mvc.perform(get("/api/v1/me/account-removal/options").header("Authorization","Bearer "+f.human().token().accessToken()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.selectionRequired").value(true)).andExpect(header().string("Cache-Control","no-store"));
        mvc.perform(post("/api/v1/accounts/"+f.account().accountId()+"/restore").contentType("application/json").content("{\"password\":\""+ORG_PASSWORD+"\"}"))
                .andExpect(status().isUnauthorized());
    }
    @Test void neitherLegacyOwnerNorAppointedStudentAdminCanRemoveBlacklistOrRestoreStudents() {
        Fixture f=fixture();
        for(LifecycleRequests.Action action:LifecycleRequests.Action.values()) {
            assertThatThrownBy(()->action(f,action,action==LifecycleRequests.Action.BLACKLIST?Instant.now().plusSeconds(300):null)).isInstanceOf(LifecycleFailure.class);
        }
        TokenResponse admin=StudentFixture.administrator(application,f.owner().token(),PASSWORD,f.org().id());
        assertThatThrownBy(()->lifecycle.adminAction(admin.sessionId(),admin.loginAccountId(),f.org().id(),f.account().membershipId(),
                new LifecycleRequests.AdminAction(admin.loginAccountId(),LifecycleRequests.Action.REMOVE,null,"Denied student management",PASSWORD)))
                .isInstanceOf(LifecycleFailure.class);
        assertThat(accountStatus(f.account().accountId())).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT status FROM iam_student_state WHERE account_id=?",String.class,bytes(f.account().accountId()))).isEqualTo("ACTIVE");
        assertThat(count("organization_account_restriction")).isZero();
    }
    @Test void verifiedTerminationRemovalIsIdempotentRevokesGrantsAndPreservesThePersonalRoot() {
        Fixture f=fixture();UUID proof=proof(f,"STUDENTSHIP_TERMINATION",null);
        UUID request=UUID.randomUUID();
        com.unidocs.auth.student.StudentPlatformService.Result first=decision(f,proof,request,"REMOVE_TERMINATED",1);
        assertThat(first.status()).isEqualTo("REMOVED_TERMINATED");
        assertThat(decision(f,proof,request,"REMOVE_TERMINATED",1)).isEqualTo(first);
        assertThat(accountStatus(f.account().accountId())).isEqualTo("SOFT_DELETED");
        assertThat(accountStatus(f.human().identity().accountId())).isEqualTo("ACTIVE");
        assertThatThrownBy(()->authentication.me(f.orgToken().sessionId(),f.account().accountId())).isInstanceOf(AuthenticationFailure.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_student_decision WHERE organization_id=?",Integer.class,bytes(f.org().id()))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_student_notice WHERE organization_id=? AND event_type='STUDENT_ENFORCEMENT_CHANGED' AND recipient_account_id=?",Integer.class,bytes(f.org().id()),bytes(f.account().accountId()))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT TIMESTAMPDIFF(SECOND,updated_at,retain_until) FROM user_account WHERE id=?",Long.class,bytes(f.account().accountId()))).isBetween(604799L,604801L);
    }
    @Test void anEscalatedViolationOnlyRestrictsCollaborationAndCannotAuthorizeStudentRemoval() {
        Fixture f=fixture();UUID report=escalatedReport(f);UUID proof=proof(f,"POLICY_VIOLATION",report);
        assertThat(decision(f,proof,UUID.randomUUID(),"RESTRICT",1).status()).isEqualTo("COLLABORATION_RESTRICTED");
        assertThat(accountStatus(f.account().accountId())).isEqualTo("ACTIVE");
        assertThat(authentication.me(f.orgToken().sessionId(),f.account().accountId()).userId()).isEqualTo(f.human().identity().userId());
        assertThat(jdbc.queryForObject("SELECT status FROM organization_membership WHERE id=?",String.class,bytes(f.account().membershipId()))).isEqualTo("ACTIVE");
        assertThatThrownBy(()->decision(f,proof,UUID.randomUUID(),"REMOVE_TERMINATED",2)).isInstanceOf(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class);
        assertThatThrownBy(()->decision(f,proof,UUID.randomUUID(),"REMOVE_INTRUDER",2)).isInstanceOf(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class);
        assertThat(decision(f,proof,UUID.randomUUID(),"REVERSE",2).status()).isEqualTo("ACTIVE");
        assertThat(count("organization_account_restriction")).isZero();
    }
    @Test void reportRecommendationsAndUnconfirmedEvidenceCannotChangeAStudentsPermissions() {
        Fixture f=fixture();UUID report=escalatedReport(f);
        assertThat(jdbc.queryForObject("SELECT status FROM iam_student_state WHERE account_id=?",String.class,bytes(f.account().accountId()))).isEqualTo("ACTIVE");
        assertThatThrownBy(()->StudentFixture.developer(application,f.owner().token(),PASSWORD,p->
            application.getBean(com.unidocs.auth.student.StudentPlatformService.class).verifyProof(currentJwt(),p,f.org().id(),
                new com.unidocs.auth.student.StudentPlatformService.ProofCommand(UUID.randomUUID(),f.account().accountId(),report,"POLICY_VIOLATION","private/unconfirmed",false))))
                .isInstanceOf(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class);
        assertThat(count("iam_student_enforcement_proof")).isZero();
        assertThat(count("iam_student_decision")).isZero();
    }
    @Test void enforcementOutboxFailureRollsBackStateNoticesAndDecisionTogether() {
        Fixture f=fixture();UUID proof=proof(f,"STUDENTSHIP_TERMINATION",null);
        doThrow(new org.springframework.dao.DataAccessResourceFailureException("Injected outbox failure"))
                .when(outbox).lifecycle(eq("ORGANIZATION"),eq(f.org().id()),anyLong(),eq("STUDENT_ENFORCEMENT_CHANGED"),any(),any(),any(),any());
        assertThatThrownBy(()->decision(f,proof,UUID.randomUUID(),"REMOVE_TERMINATED",1)).isInstanceOf(org.springframework.dao.DataAccessResourceFailureException.class);
        assertThat(accountStatus(f.account().accountId())).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT status FROM iam_student_state WHERE account_id=?",String.class,bytes(f.account().accountId()))).isEqualTo("ACTIVE");
        assertThat(count("iam_student_decision")).isZero();
        assertThat(count("organization_account_restriction")).isZero();
        assertThat(authentication.me(f.orgToken().sessionId(),f.account().accountId()).userId()).isEqualTo(f.human().identity().userId());
    }
    private org.springframework.security.oauth2.jwt.Jwt currentJwt() {
        return (org.springframework.security.oauth2.jwt.Jwt)org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }
    private UUID proof(Fixture f,String kind,UUID report) {
        return StudentFixture.developer(application,f.owner().token(),PASSWORD,p->
                application.getBean(com.unidocs.auth.student.StudentPlatformService.class).verifyProof(currentJwt(),p,f.org().id(),
                        new com.unidocs.auth.student.StudentPlatformService.ProofCommand(UUID.randomUUID(),f.account().accountId(),report,kind,"private/verified-fixture",true)));
    }
    private com.unidocs.auth.student.StudentPlatformService.Result decision(Fixture f,UUID proof,UUID request,String action,long version) {
        return StudentFixture.developer(application,f.owner().token(),PASSWORD,p->
                application.getBean(com.unidocs.auth.student.StudentPlatformService.class).enforce(currentJwt(),p,f.org().id(),
                        new com.unidocs.auth.student.StudentPlatformService.Decision(request,f.account().accountId(),proof,action,version)));
    }
    private UUID escalatedReport(Fixture f) {
        UUID semester=UUID.randomUUID(),course=UUID.randomUUID(),report=UUID.randomUUID();
        jdbc.update("INSERT INTO academic_semester VALUES(?,?,?,UTC_TIMESTAMP(6)-INTERVAL 1 DAY,UTC_TIMESTAMP(6)+INTERVAL 1 DAY)",bytes(semester),bytes(f.org().id()),"fixture-"+semester.toString().substring(0,8));
        jdbc.update("INSERT INTO iam_group(id,organization_id,name,type,status,version,created_by_account_id,creation_request_id,creation_fingerprint,created_at,updated_at) VALUES(?,?,'Report fixture','COURSE','ACTIVE',1,?,?,REPEAT('a',64),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))",bytes(course),bytes(f.org().id()),bytes(f.owner().identity().accountId()),bytes(UUID.randomUUID()));
        jdbc.update("INSERT INTO iam_course_offering(group_id,organization_id,semester_id,status,workspace_status) VALUES(?,?,?,'OFFERED','READY')",bytes(course),bytes(f.org().id()),bytes(semester));
        jdbc.update("INSERT INTO iam_student_report(id,organization_id,course_id,reporter_account_id,target_account_id,evidence_reference,request_id,status) VALUES(?,?,?,?,?,?,?,'ESCALATED')",bytes(report),bytes(f.org().id()),bytes(course),bytes(f.owner().identity().accountId()),bytes(f.account().accountId()),UUID.randomUUID().toString(),bytes(UUID.randomUUID()));
        return report;
    }
    @TestConfiguration(proxyBeanMethods=false)
    static class NoticeConfiguration { @Bean @Primary CapturingNotices securityNotices() { return new CapturingNotices(); } }
    static class CapturingNotices implements AccountNoticeDelivery {
        boolean enabled=true;boolean fail;final List<LifecycleRepository.Notice> sent=new CopyOnWriteArrayList<>();
        public boolean enabled() { return enabled; }
        public void deliver(String email,LifecycleRepository.Notice notice) {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            if(fail) throw new IllegalStateException("smtp-secret");sent.add(notice);
        }
    }
}
