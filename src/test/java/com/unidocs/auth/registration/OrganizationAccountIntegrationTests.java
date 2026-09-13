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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;

import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.account.api.*;
import com.unidocs.auth.account.application.*;
import com.unidocs.auth.account.application.LinkedAccountService.ActionResponse;
import com.unidocs.auth.account.application.LinkedAccountService.ChallengeResponse;
import com.unidocs.auth.account.domain.AccountChallenge.*;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.*;
import com.unidocs.auth.organization.api.*;
import com.unidocs.auth.organization.api.InvitationResponse;
import com.unidocs.auth.organization.api.OrganizationAccountRequest;
import com.unidocs.auth.organization.api.OrganizationAccountResponse;
import com.unidocs.auth.organization.api.OrganizationResponse;
import com.unidocs.auth.organization.application.*;
import com.unidocs.auth.organization.domain.*;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.api.RegistrationCompletionResponse;
import com.unidocs.auth.registration.api.RegistrationResponse;
import com.unidocs.auth.registration.application.*;
import com.unidocs.auth.session.persistence.SessionRepository.Account;

import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Import({RegistrationIntegrationTests.DeliveryConfiguration.class,InvitationIntegrationTests.DeliveryConfiguration.class})
@org.junit.jupiter.api.extension.ExtendWith(OutputCaptureExtension.class)
class OrganizationAccountIntegrationTests extends MySqlIntegrationTest {
    static final String PERSONAL_PASSWORD="test-password-long";
    static final String ORGANIZATION_PASSWORD="independent-org-password";
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery registrationMail;
    @Autowired InvitationIntegrationTests.CapturingInvitations invitationMail;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired InvitationService invitations;
    @Autowired OrganizationAccountService accounts;
    @Autowired LinkedAccountService linked;
    @Autowired JwtDecoder decoder;
    @Autowired MockMvc mvc;
    @Autowired org.springframework.transaction.PlatformTransactionManager manager;
    @MockitoSpyBean OutboxRepository outbox;
    Actor owner;
    Actor human;
    OrganizationResponse organization;
    InvitationResponse invitation;
    String invitedEmail;
    record Actor(RegistrationCompletionResponse identity,TokenResponse token,String email) { }
    @BeforeEach void setup() {
        invitationMail.fail=false;
        owner=actor(); human=actor();
        // Phase 3 admits students through mailbox verification or evidence review.
        organization=organization("institution",Organization.Type.UNIVERSITY);
        invitedEmail="work-"+UUID.randomUUID()+"@example.com";

    }
    Actor actor() {
        String email=UUID.randomUUID()+"@example.com";
        RegistrationResponse pending=registrations.register(new RegistrationRequest("Human",email,PERSONAL_PASSWORD));
        String proof=registrationMail.tokens.get(pending.id());
        registrations.verify(pending.id(),new VerificationRequest(proof));
        RegistrationCompletionResponse identity=provisioning.complete(pending.id(),new RegistrationCompletionRequest(proof));
        return new Actor(identity,authentication.login(new LoginRequest(email,PERSONAL_PASSWORD)),email);
    }
    OrganizationResponse organization(String slug,Organization.Type type) {
        return organizations.create(owner.token().sessionId(),owner.identity().accountId(),new OrganizationRequest(owner.identity().accountId(),UUID.randomUUID(),"Organization",slug,type));
    }
    InvitationResponse invite(UUID org,String email) {
        return invitations.issue(owner.token().sessionId(),owner.identity().accountId(),org,new InvitationRequest(owner.identity().accountId(),email));
    }
    OrganizationAccountRequest request(InvitationResponse invitation) {
        return new OrganizationAccountRequest(human.identity().accountId(),invitationMail.proofs.get(invitation.id()),"My organization account",ORGANIZATION_PASSWORD);
    }
    OrganizationAccountResponse provision() { return accounts.provision(human.token().sessionId(),human.identity().accountId(),organization.id(),invitation.id(),request(invitation)); }
    LinkedAccountService.ActionResponse prove(TokenResponse actor,UUID target,Purpose purpose,Method method,String secret,String pin) {
        ChallengeResponse challenge=linked.challenge(actor.sessionId(),actor.loginAccountId(),target,new ChallengeRequest(purpose,method));
        return linked.complete(actor.sessionId(),actor.loginAccountId(),target,challenge.id(),new AccountProofRequest(secret,pin));
    }
    TokenResponse organizationLogin(UUID account) { return authentication.loginAccount(account,new AccountLoginRequest(ORGANIZATION_PASSWORD)); }
    int count(String table) { return jdbc.queryForObject("SELECT COUNT(*) FROM "+table,Integer.class); }
    @Test void retiredInvitationProvisioningCannotCreateAUniversityAccount() {
        int accountsBefore=count("user_account"),membersBefore=count("organization_membership"),identitiesBefore=count("login_identity");
        assertThatThrownBy(()->accounts.provision(human.token().sessionId(),human.identity().accountId(),organization.id(),UUID.randomUUID(),
                new OrganizationAccountRequest(human.identity().accountId(),"obsolete-invitation-proof","Denied student account",ORGANIZATION_PASSWORD)))
                .isInstanceOf(OrganizationFailure.class).extracting("status").isEqualTo(org.springframework.http.HttpStatus.FORBIDDEN);
        assertThat(count("user_account")).isEqualTo(accountsBefore);
        assertThat(count("organization_membership")).isEqualTo(membersBefore);
        assertThat(count("login_identity")).isEqualTo(identitiesBefore);
    }
    @Test void legacyOwnerCannotReopenStudentProvisioningThroughAnAdministrativeInvite() {
        assertThatThrownBy(()->invite(organization.id(),human.email())).isInstanceOf(OrganizationFailure.class)
                .extracting("status").isEqualTo(org.springframework.http.HttpStatus.FORBIDDEN);
        assertThat(count("organization_invitation")).isZero();
    }
}