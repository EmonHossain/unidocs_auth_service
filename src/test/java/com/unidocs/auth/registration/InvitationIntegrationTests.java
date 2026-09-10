package com.unidocs.auth.registration;

import java.util.*;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.*;
import org.springframework.boot.test.system.*;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.*;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.account.application.LinkedAccountService.ChallengeResponse;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.organization.api.*;
import com.unidocs.auth.organization.api.InvitationRequest;
import com.unidocs.auth.organization.api.InvitationResponse;
import com.unidocs.auth.organization.api.OrganizationResponse;
import com.unidocs.auth.organization.application.*;
import com.unidocs.auth.organization.domain.*;
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
@Import({RegistrationIntegrationTests.DeliveryConfiguration.class,InvitationIntegrationTests.DeliveryConfiguration.class})
@org.junit.jupiter.api.extension.ExtendWith(OutputCaptureExtension.class)
class InvitationIntegrationTests extends MySqlIntegrationTest {
    @Test void professionalOrganizationsRejectExternalInvitationAdmission() {
        OrganizationResponse company=organizations.create(owner.token().sessionId(),owner.identity().accountId(),
                new OrganizationRequest(owner.identity().accountId(),UUID.randomUUID(),"Professional","professional-"+UUID.randomUUID(),Organization.Type.COMPANY));
        assertThatThrownBy(()->invitations.issue(owner.token().sessionId(),owner.identity().accountId(),company.id(),
                new InvitationRequest(owner.identity().accountId(),recipient.email()))).isInstanceOf(OrganizationFailure.class);
    }
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery registrationDelivery;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired InvitationService invitations;
    @Autowired com.unidocs.auth.account.application.LinkedAccountService linked;
    @Autowired CapturingInvitations mail;
    @Autowired InvitationTokens tokens;
    @Autowired MockMvc mvc;
    @Autowired org.springframework.transaction.PlatformTransactionManager manager;
    @MockitoSpyBean OutboxRepository outbox;
    Actor owner;
    Actor recipient;
    OrganizationResponse organization;
    record Actor(RegistrationCompletionResponse identity,TokenResponse token,String email) { }
    @BeforeEach void provision() {
        mail.fail=false;
        owner=actor(); recipient=actor();
        organization=organizations.create(owner.token().sessionId(),owner.identity().accountId(),
            new OrganizationRequest(owner.identity().accountId(),UUID.randomUUID(),"Inviting Org","inviting-org",Organization.Type.UNIVERSITY));
    }
    Actor actor() {
        String email=UUID.randomUUID()+"@example.com";
        RegistrationResponse pending=registrations.register(new RegistrationRequest("Human",email,"test-password-long"));
        String proof=registrationDelivery.tokens.get(pending.id());
        registrations.verify(pending.id(),new VerificationRequest(proof));
        RegistrationCompletionResponse identity=provisioning.complete(pending.id(),new RegistrationCompletionRequest(proof));
        return new Actor(identity,authentication.login(new LoginRequest(email,"test-password-long")),email);
    }
    InvitationResponse invite() {
        return invitations.issue(owner.token().sessionId(),owner.identity().accountId(),organization.id(),
            new InvitationRequest(owner.identity().accountId(),recipient.email().toUpperCase(Locale.ROOT)));
    }
    OrganizationResponse accept(InvitationResponse invite,String proof) {
        return invitations.accept(recipient.token().sessionId(),recipient.identity().accountId(),organization.id(),invite.id(),
            new InvitationAcceptanceRequest(recipient.identity().accountId(),proof));
    }
    OrganizationResponse accept(InvitationResponse invite) { return accept(invite,mail.proofs.get(invite.id())); }
    int count(String table) { return jdbc.queryForObject("SELECT COUNT(*) FROM "+table,Integer.class); }
    String invitationStatus(UUID id) { return jdbc.queryForObject("SELECT status FROM organization_invitation WHERE id=?",String.class,bytes(id)); }
    @Test void legacyInstitutionOwnerCannotInviteAStudentOrSendAnAdmissionProof() {
        int invitationsBefore=count("organization_invitation"),membersBefore=count("organization_membership");
        int messages=mail.proofs.size();
        assertThatThrownBy(this::invite).isInstanceOf(OrganizationFailure.class).extracting("status").isEqualTo(org.springframework.http.HttpStatus.FORBIDDEN);
        assertThat(count("organization_invitation")).isEqualTo(invitationsBefore);
        assertThat(count("organization_membership")).isEqualTo(membersBefore);
        assertThat(mail.proofs).hasSize(messages);
    }
    @Test void retiredAcceptanceCannotCreateMembershipOrGrantUsingAnInvitationIdentifier() {
        int members=count("organization_membership"),grants=count("session_account_grant");
        assertThatThrownBy(()->invitations.accept(recipient.token().sessionId(),recipient.identity().accountId(),organization.id(),UUID.randomUUID(),
                new InvitationAcceptanceRequest(recipient.identity().accountId(),"obsolete-invitation-proof")))
                .isInstanceOf(OrganizationFailure.class).extracting("status").isEqualTo(org.springframework.http.HttpStatus.FORBIDDEN);
        assertThat(count("organization_membership")).isEqualTo(members);
        assertThat(count("session_account_grant")).isEqualTo(grants);
    }
    @Test void ambientTransactionsStillFailBeforeRetiredInvitationDelivery() {
        TransactionTemplate transaction=new TransactionTemplate(manager);
        assertThatThrownBy(()->transaction.execute(status->invite())).isInstanceOf(org.springframework.transaction.IllegalTransactionStateException.class);
    }
    @TestConfiguration(proxyBeanMethods=false)
    static class DeliveryConfiguration {
        @Bean CapturingInvitations capturingInvitations() { return new CapturingInvitations(); }
    }
    static class CapturingInvitations implements InvitationDelivery {
        final Map<UUID,String> proofs=new ConcurrentHashMap<>(); boolean fail;
        public void deliver(String email,UUID organization,UUID invitation,String token,java.time.Instant expiresAt) {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            if(fail) throw new IllegalStateException("Simulated unavailable delivery");
            proofs.put(invitation,token);
        }
    }
}
