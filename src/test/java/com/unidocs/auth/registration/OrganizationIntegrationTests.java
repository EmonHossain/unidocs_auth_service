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
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;

import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.account.application.LinkedAccountService.ChallengeResponse;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.organization.api.*;
import com.unidocs.auth.organization.api.OrganizationRequest;
import com.unidocs.auth.organization.api.OrganizationResponse;
import com.unidocs.auth.organization.application.*;
import com.unidocs.auth.organization.application.OrganizationService.Page;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
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
class OrganizationIntegrationTests extends MySqlIntegrationTest {
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired InvitationService invitations;
    @Autowired com.unidocs.auth.account.application.LinkedAccountService linked;
    @Autowired MockMvc mvc;
    @Autowired org.springframework.transaction.PlatformTransactionManager manager;
    @MockitoSpyBean OutboxRepository outbox;
    RegistrationCompletionResponse identity;
    TokenResponse token;
    @BeforeEach void provision() {
        String email=UUID.randomUUID()+"@example.com";
        RegistrationResponse pending=registrations.register(new RegistrationRequest("Founder",email,"test-password-long"));
        String proof=delivery.tokens.get(pending.id());
        registrations.verify(pending.id(),new VerificationRequest(proof));
        identity=provisioning.complete(pending.id(),new RegistrationCompletionRequest(proof));
        token=authentication.login(new LoginRequest(email,"test-password-long"));
    }
    OrganizationRequest request(String slug) { return new OrganizationRequest(identity.accountId(),UUID.randomUUID(),"Example Org",slug,Organization.Type.COMPANY); }
    OrganizationResponse create(OrganizationRequest request) { return organizations.create(token.sessionId(),identity.accountId(),request); }
    @Test void invitationCreationFailsClosedWithoutMailProvider() {
        OrganizationResponse organization=create(request("no-mail"));
        assertThatThrownBy(()->invitations.issue(token.sessionId(),identity.accountId(),organization.id(),new InvitationRequest(identity.accountId(),"member@example.com")))
            .isInstanceOf(OrganizationFailure.class).extracting("status").isEqualTo(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(count("organization_invitation")).isZero();
    }
    int count(String table) { return jdbc.queryForObject("SELECT COUNT(*) FROM "+table,Integer.class); }
    @Test void creationIsDurableIdempotentAndQueuesOneSanitizedEvent() throws Exception {
        OrganizationRequest request=request("example");
        OrganizationResponse result=create(request);
        assertThat(create(request)).isEqualTo(result);
        assertThat(result.role().name()).isEqualTo("OWNER");
        assertThat(result.membershipVersion()).isEqualTo(1);
        for(String table:List.of("organization","organization_auth_policy","organization_membership","outbox_event","user_account","user_session","session_account_grant"))
            assertThat(count(table)).as(table).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type LIKE 'ORGANIZATION_%'",Integer.class)).isEqualTo(2);
        String payload=jdbc.queryForObject("SELECT payload FROM outbox_event WHERE status='PENDING'",String.class);
        assertThat(payload).contains(result.id().toString(),result.membershipId().toString(),"aggregateVersion").doesNotContain("@","Example Org",token.accessToken());
        mvc.perform(get("/api/v1/organizations/"+result.id()).param("accountId",identity.accountId().toString()).header("Authorization","Bearer "+token.accessToken()))
            .andExpect(status().isOk()).andExpect(header().string("Cache-Control","no-store"))
            .andExpect(jsonPath("$.officialEmail").doesNotExist());
        assertThatThrownBy(()->create(new OrganizationRequest(request.accountId(),request.requestId(),"Changed",request.slug(),request.type())))
            .isInstanceOf(OrganizationFailure.class).extracting("status").isEqualTo(org.springframework.http.HttpStatus.CONFLICT);
        assertThatThrownBy(()->create(request("example"))).isInstanceOf(OrganizationFailure.class);
        assertThat(count("organization")).isEqualTo(1);
    }
    @Test void paginationAndAccountIsolation() {
        create(request("first")); create(request("second")); create(request("third"));
        Page first=organizations.list(token.sessionId(),identity.accountId(),identity.accountId(),null,2);
        Page second=organizations.list(token.sessionId(),identity.accountId(),identity.accountId(),first.nextCursor(),2);
        assertThat(first.organizations()).hasSize(2);
        assertThat(second.organizations()).hasSize(1).doesNotContainAnyElementsOf(first.organizations());
        assertThat(second.nextCursor()).isNull();
        assertThatThrownBy(()->organizations.list(token.sessionId(),identity.accountId(),UUID.randomUUID(),null,2)).isInstanceOf(OrganizationFailure.class);
    }
    @Test void anotherHumanCannotReadOrListAndSlugCollisionDoesNotCreateMembership() throws Exception {
        OrganizationResponse result=create(request("shared-slug"));
        String email=UUID.randomUUID()+"@example.com";
        RegistrationResponse pending=registrations.register(new RegistrationRequest("Other",email,"test-password-long"));
        String proof=delivery.tokens.get(pending.id());
        registrations.verify(pending.id(),new VerificationRequest(proof));
        RegistrationCompletionResponse other=provisioning.complete(pending.id(),new RegistrationCompletionRequest(proof));
        TokenResponse login=authentication.login(new LoginRequest(email,"test-password-long"));
        assertThatThrownBy(()->organizations.get(login.sessionId(),other.accountId(),other.accountId(),result.id())).isInstanceOf(OrganizationFailure.class);
        assertThatThrownBy(()->organizations.get(login.sessionId(),other.accountId(),identity.accountId(),result.id())).isInstanceOf(OrganizationFailure.class);
        assertThat(organizations.list(login.sessionId(),other.accountId(),other.accountId(),null,10).organizations()).isEmpty();
        assertThatThrownBy(()->organizations.create(login.sessionId(),other.accountId(),
            new OrganizationRequest(other.accountId(),UUID.randomUUID(),"Other Name","shared-slug",Organization.Type.CUSTOM))).isInstanceOf(OrganizationFailure.class);
        assertThat(count("organization_membership")).isEqualTo(1);
        mvc.perform(get("/api/v1/organizations/"+result.id()).param("accountId",other.accountId().toString()).header("Authorization","Bearer "+login.accessToken()))
            .andExpect(status().isForbidden()).andExpect(jsonPath("$.name").doesNotExist());
    }
    @ParameterizedTest
    @ValueSource(strings={"UPDATE organization SET status='DISABLED'",
        "UPDATE organization_membership SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6),revoked_by=id",
        "UPDATE organization_auth_policy SET enabled=false",
        "UPDATE organization_auth_policy SET require_mfa=true",
        "UPDATE organization_auth_policy SET email_domain='example.com'"})
    void currentMembershipAndPolicyFailClosed(String mutation) {
        OrganizationResponse result=create(request("hidden")); jdbc.update(mutation);
        assertThatThrownBy(()->organizations.get(token.sessionId(),identity.accountId(),identity.accountId(),result.id())).isInstanceOf(OrganizationFailure.class);
        assertThat(organizations.list(token.sessionId(),identity.accountId(),identity.accountId(),null,10).organizations()).isEmpty();
    }
    @Test void unverifiedContactCannotBootstrap() {
        jdbc.update("UPDATE user_contact SET verified=false");
        assertThatThrownBy(()->create(request("unverified"))).isInstanceOf(OrganizationFailure.class);
        assertThat(count("organization")).isZero();
    }
    @Test void preferredLinkedAccountWithoutGrantConfersNoOrganizationAccess() {
        OrganizationResponse result=create(request("locked"));
        UUID locked=UUID.randomUUID();
        jdbc.update("""
            INSERT INTO user_account(id,user_id,type,display_name,status,created_at,updated_at)
            VALUES (?,?,'PERSONAL','Locked','ACTIVE',UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))
            """,bytes(locked),bytes(identity.userId()));
        jdbc.update("""
            INSERT INTO account_group_member(account_id,account_group_id,status,link_method,linked_by_account_id,linked_at)
            VALUES (?,?,'LINKED','REGISTRATION',?,UTC_TIMESTAMP(6))
            """,bytes(locked),bytes(identity.accountGroupId()),bytes(identity.accountId()));
        jdbc.update("UPDATE user_preference SET preferred_account_id=?",bytes(locked));
        jdbc.update("UPDATE organization_membership SET account_id=?",bytes(locked));
        assertThatThrownBy(()->organizations.get(token.sessionId(),identity.accountId(),locked,result.id())).isInstanceOf(OrganizationFailure.class);
        assertThatThrownBy(()->create(new OrganizationRequest(locked,UUID.randomUUID(),"Locked","locked-create",Organization.Type.COMPANY))).isInstanceOf(OrganizationFailure.class);
        assertThat(organizations.list(token.sessionId(),identity.accountId(),identity.accountId(),null,10).organizations()).isEmpty();
        assertThat(count("organization")).isEqualTo(1);
    }
    @Test void pinGrantRequiresExplicitPolicyAndCannotBootstrap() {
        OrganizationResponse result=create(request("password-policy"));
        ChallengeResponse setup=linked.challenge(token.sessionId(),identity.accountId(),identity.accountId(),
            new com.unidocs.auth.account.api.ChallengeRequest(com.unidocs.auth.account.domain.AccountChallenge.Purpose.SET_PIN,com.unidocs.auth.account.domain.AccountChallenge.Method.PASSWORD));
        linked.complete(token.sessionId(),identity.accountId(),identity.accountId(),setup.id(),new com.unidocs.auth.account.api.AccountProofRequest("test-password-long","859271"));
        ChallengeResponse unlock=linked.challenge(token.sessionId(),identity.accountId(),identity.accountId(),
            new com.unidocs.auth.account.api.ChallengeRequest(com.unidocs.auth.account.domain.AccountChallenge.Purpose.UNLOCK,com.unidocs.auth.account.domain.AccountChallenge.Method.PIN));
        linked.complete(token.sessionId(),identity.accountId(),identity.accountId(),unlock.id(),new com.unidocs.auth.account.api.AccountProofRequest("859271",null));
        assertThatThrownBy(()->create(request("pin-create"))).isInstanceOf(OrganizationFailure.class);
        assertThatThrownBy(()->organizations.get(token.sessionId(),identity.accountId(),identity.accountId(),result.id())).isInstanceOf(OrganizationFailure.class);
        assertThat(organizations.list(token.sessionId(),identity.accountId(),identity.accountId(),null,10).organizations()).isEmpty();
        jdbc.update("UPDATE organization_auth_policy SET allow_pin_unlock=true");
        assertThat(organizations.get(token.sessionId(),identity.accountId(),identity.accountId(),result.id()).id()).isEqualTo(result.id());
    }
    @Test void atomicRollbackIncludesAuditsAndCanRetry() {
        OrganizationRequest request=request("rollback");
        doThrow(new org.springframework.dao.DataAccessResourceFailureException("Injected failure"))
            .when(outbox).organizationCreated(any(),any(),any(),any());
        assertThatThrownBy(()->create(request)).isInstanceOf(org.springframework.dao.DataAccessResourceFailureException.class);
        for(String table:List.of("organization","organization_membership","organization_auth_policy","outbox_event")) assertThat(count(table)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type LIKE 'ORGANIZATION_%'",Integer.class)).isZero();
        reset(outbox); assertThat(create(request).id()).isNotNull();
    }
    @Test void concurrentRetriesReturnOneOrganization() throws Exception {
        OrganizationRequest request=request("concurrent");
        try(ExecutorService executor=Executors.newFixedThreadPool(2)) {
            CountDownLatch start=new CountDownLatch(1);
            List<Future<OrganizationResponse>> tasks=List.of(executor.submit(()->{start.await(); return create(request);}),executor.submit(()->{start.await(); return create(request);}));
            start.countDown();
            assertThat(tasks.getFirst().get(20,TimeUnit.SECONDS)).isEqualTo(tasks.getLast().get(20,TimeUnit.SECONDS));
        }
        assertThat(count("organization")).isEqualTo(1); assertThat(count("outbox_event")).isEqualTo(1);
    }
    @Test void apiAuthenticationValidationAndCreate() throws Exception {
        String body="""
            {"accountId":"%s","requestId":"%s","name":"API Org","slug":"api-org","type":"CUSTOM"}
            """.formatted(identity.accountId(),UUID.randomUUID());
        mvc.perform(post("/api/v1/organizations").contentType("application/json").content(body)).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/organizations").header("Authorization","Bearer "+token.accessToken()).contentType("application/json").content(body.replace("api-org","Invalid Slug")))
            .andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/organizations").header("Authorization","Bearer "+token.accessToken()).contentType("application/json").content(body))
            .andExpect(status().isCreated()).andExpect(header().exists("Location")).andExpect(jsonPath("$.role").value("OWNER"));
        mvc.perform(get("/api/v1/me/organizations").param("accountId",identity.accountId().toString()).param("limit","0").header("Authorization","Bearer "+token.accessToken()))
            .andExpect(status().isBadRequest());
    }
    @Test void ambientTransactionsAreRejected() {
        TransactionTemplate transaction=new org.springframework.transaction.support.TransactionTemplate(manager);
        assertThatThrownBy(()->transaction.execute(s->create(request("ambient"))))
            .isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
        assertThat(count("organization")).isZero();
    }
    @Test void memberCannotProvisionEmployeesUsingInjectedRolesOrAnotherOwnersAccount() throws Exception {
        OrganizationResponse organization=create(request("privilege-"+UUID.randomUUID()));
        String otherEmail=UUID.randomUUID()+"@example.com";
        RegistrationResponse pending=registrations.register(new RegistrationRequest("Other human",otherEmail,"test-password-long"));
        String proof=delivery.tokens.get(pending.id());
        registrations.verify(pending.id(),new VerificationRequest(proof));
        RegistrationCompletionResponse other=provisioning.complete(pending.id(),new RegistrationCompletionRequest(proof));
        TokenResponse otherToken=authentication.login(new LoginRequest(otherEmail,"test-password-long"));
        organizations.create(otherToken.sessionId(),other.accountId(),new OrganizationRequest(other.accountId(),UUID.randomUUID(),"Other tenant","other-"+UUID.randomUUID(),Organization.Type.COMPANY));
        jdbc.update("UPDATE organization_membership SET role='MEMBER' WHERE id=?",bytes(organization.membershipId()));
        int events=jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event",Integer.class);
        int audits=jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event",Integer.class);
        for(UUID admin : List.of(identity.accountId(),other.accountId())) {
            mvc.perform(post("/api/v1/organizations/"+organization.id()+"/employees")
                    .header("Authorization","Bearer "+token.accessToken()).header("X-User-Id",other.userId().toString())
                    .contentType("application/json").content("{\"adminAccountId\":\""+admin+"\",\"requestId\":\""+UUID.randomUUID()
                        +"\",\"displayName\":\"Injected employee\",\"role\":\"OWNER\",\"authorities\":[\"ROLE_ADMIN\"]}"))
                    .andExpect(status().isForbidden());
        }
        assertThat(jdbc.queryForObject("SELECT role FROM organization_membership WHERE id=?",String.class,bytes(organization.membershipId()))).isEqualTo("MEMBER");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM employee_activation",Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event",Integer.class)).isEqualTo(events);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event",Integer.class)).isEqualTo(audits);
    }

}
