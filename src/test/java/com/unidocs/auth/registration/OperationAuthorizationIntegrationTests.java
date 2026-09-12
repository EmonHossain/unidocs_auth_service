package com.unidocs.auth.registration;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.time.Instant;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authentication.api.LoginRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.authorization.api.OperationAuthorizationRequest;
import com.unidocs.auth.authorization.api.OperationAuthorizationResponse;
import com.unidocs.auth.authorization.api.IndividualRecipientRequest;
import com.unidocs.auth.authorization.api.IndividualRecipientResponse;
import com.unidocs.auth.group.personal.PersonalGroupService;
import com.unidocs.auth.authorization.application.*;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.application.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
class OperationAuthorizationIntegrationTests extends MySqlIntegrationTest {
    @Autowired RegistrationService registration;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired OperationAuthorizationService authorization;
    @Autowired PlatformTransactionManager manager;
    @Autowired PersonalGroupService personalGroups;
    @Autowired @org.springframework.beans.factory.annotation.Qualifier("jwtDecoder") JwtDecoder users;
    private TokenResponse login;
    private JwtAuthenticationToken service;
    private UUID ceiling;
    private UUID share;

    @BeforeEach void actor() {
        String email = UUID.randomUUID() + "@example.test";
        RegistrationResponse pending = registration.register(new RegistrationRequest("Actor", email, "LongStrongPassword!2026"));
        String token = delivery.tokens.get(pending.id());
        registration.verify(pending.id(), new VerificationRequest(token));
        provisioning.complete(pending.id(), new RegistrationCompletionRequest(token));
        login = authentication.login(new LoginRequest(email, "LongStrongPassword!2026"));
        Jwt principal = Jwt.withTokenValue("service-fixture").header("alg", "RS256").subject("document-service")
                .claim("azp", "document-service").issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        service = new JwtAuthenticationToken(principal, List.of(new SimpleGrantedAuthority("SCOPE_iam.authorization.read")));
        SecurityContextHolder.getContext().setAuthentication(service);
        ceiling = UUID.fromString(jdbc.queryForObject("SELECT BIN_TO_UUID(role_id) FROM iam_stakeholder_role_binding WHERE category_key='INDIVIDUAL'", String.class));
        share = UUID.fromString(jdbc.queryForObject("SELECT BIN_TO_UUID(id) FROM iam_authority WHERE service_id='document-service' AND authority_key='file.share'", String.class));
    }

    @AfterEach void restore() {
        new TransactionTemplate(manager).executeWithoutResult(transaction -> {
            jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE", Long.class);
            jdbc.update("INSERT IGNORE INTO iam_role_authority VALUES (?,?)", bytes(ceiling), bytes(share));
            jdbc.update("UPDATE iam_role SET version=version+1 WHERE id=?", bytes(ceiling));
            jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
        });
        SecurityContextHolder.clearContext();
    }

    @Test void realSessionEstablishesImmediateExpiryEvidenceAndFreshCapabilityRevocation() {
        OperationAuthorizationRequest request = request("file.share.view");
        OperationAuthorizationResponse before = authorization.evaluate(service, delegated(), request);
        assertThat(before.requiredAuthorities()).containsExactlyInAnyOrder("file.share", "file.share.view");
        assertThat(before.checkedAt()).isEqualTo(before.validUntil());
        assertThat(before.accountId()).isEqualTo(login.loginAccountId());
        new TransactionTemplate(manager).executeWithoutResult(transaction -> {
            jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE", Long.class);
            jdbc.update("DELETE FROM iam_role_authority WHERE role_id=? AND authority_id=?", bytes(ceiling), bytes(share));
            jdbc.update("UPDATE iam_role SET version=version+1 WHERE id=?", bytes(ceiling));
            jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
        });
        assertThatThrownBy(() -> authorization.evaluate(service, delegated(), request)).isInstanceOfSatisfying(OperationAuthorizationFailure.class,
                failure -> assertThat(failure.status()).isEqualTo(HttpStatus.FORBIDDEN));
        assertThat(authorization.evaluate(service, delegated(), request("file.read")).reasonCode()).isEqualTo("ALLOWED");
    }

    @Test void folderSharingCeilingDisablesBothModesWithoutDisablingRevocationOrFileSharing() {
        UUID folderShare = UUID.fromString(jdbc.queryForObject(
                "SELECT BIN_TO_UUID(id) FROM iam_authority WHERE service_id='document-service' AND authority_key='folder.share'", String.class));
        OperationAuthorizationRequest view = new OperationAuthorizationRequest("folder.share.view", login.loginAccountId(), "FOLDER", null, null);
        OperationAuthorizationRequest edit = new OperationAuthorizationRequest("folder.share.edit", login.loginAccountId(), "FOLDER", null, null);
        assertThat(authorization.evaluate(service, delegated(), view).requiredAuthorities())
                .containsExactlyInAnyOrder("folder.share", "folder.share.view", "file.share", "file.share.view");
        assertThat(authorization.evaluate(service, delegated(), edit).requiredAuthorities())
                .containsExactlyInAnyOrder("folder.share", "folder.share.edit", "file.share", "file.share.edit");
        try {
            new TransactionTemplate(manager).executeWithoutResult(transaction -> {
                jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE", Long.class);
                jdbc.update("DELETE FROM iam_role_authority WHERE role_id=? AND authority_id=?", bytes(ceiling), bytes(folderShare));
                jdbc.update("UPDATE iam_role SET version=version+1 WHERE id=?", bytes(ceiling));
                jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
            });
            assertThatThrownBy(() -> authorization.evaluate(service, delegated(), view)).isInstanceOf(OperationAuthorizationFailure.class);
            assertThatThrownBy(() -> authorization.evaluate(service, delegated(), edit)).isInstanceOf(OperationAuthorizationFailure.class);
            assertThat(authorization.evaluate(service, delegated(), new OperationAuthorizationRequest(
                    "folder.share.revoke", login.loginAccountId(), "FOLDER", null, null)).reasonCode()).isEqualTo("ALLOWED");
            assertThat(authorization.evaluate(service, delegated(), request("file.share.view")).reasonCode()).isEqualTo("ALLOWED");
        } finally {
            new TransactionTemplate(manager).executeWithoutResult(transaction -> {
                jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE", Long.class);
                jdbc.update("INSERT IGNORE INTO iam_role_authority VALUES (?,?)", bytes(ceiling), bytes(folderShare));
                jdbc.update("UPDATE iam_role SET version=version+1 WHERE id=?", bytes(ceiling));
                jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
            });
        }
    }

    @Test void loginTokenCannotAuthorizeLockedOrUnrelatedAccount() {
        OperationAuthorizationRequest other = new OperationAuthorizationRequest("file.read", UUID.randomUUID(), "FILE", null, null);
        assertThatThrownBy(() -> authorization.evaluate(service, delegated(), other)).isInstanceOf(OperationAuthorizationFailure.class);
        authentication.logout(login.sessionId(), login.loginAccountId());
        assertThatThrownBy(() -> authorization.evaluate(service, delegated(), request("file.read"))).isInstanceOf(AuthenticationFailure.class);
    }

    @Test void missingDelegationAndSpoofedServiceArgumentCannotAuthorize() {
        assertThatThrownBy(() -> authorization.evaluate(service, null, request("file.read"))).isInstanceOf(AuthenticationFailure.class);
        JwtAuthenticationToken spoof = new JwtAuthenticationToken(service.getToken(), service.getAuthorities());
        assertThatThrownBy(() -> authorization.evaluate(spoof, delegated(), request("file.read"))).isInstanceOf(OperationAuthorizationFailure.class);
        assertThatThrownBy(() -> authorization.evaluate(service, delegated(), request("file.unregistered"))).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void recipientLookupAllowsOnlyCurrentMembersOfTheExactSenderGroup() {
        Actor recipient=registerActor();
        PersonalGroupService.GroupView group=personalGroups.create(asUser(login),login.loginAccountId(),"Exact group",UUID.randomUUID());
        PersonalGroupService.Invitation invitation=personalGroups.invite(asUser(login),login.loginAccountId(),group.id(),recipient.login().loginAccountId(),UUID.randomUUID());
        personalGroups.respond(asUser(recipient.login()),recipient.login().loginAccountId(),invitation.id(),true);
        SecurityContextHolder.getContext().setAuthentication(service);
        IndividualRecipientResponse evidence=authorization.recipient(service,delegated(),new IndividualRecipientRequest(login.loginAccountId(),recipient.login().loginAccountId(),group.id()));
        assertThat(evidence.groupId()).isEqualTo(group.id());
        assertThat(evidence.recipientUserId()).isEqualTo(recipient.identity().userId());
        assertThat(evidence.checkedAt()).isEqualTo(evidence.validUntil());
        personalGroups.remove(asUser(login),login.loginAccountId(),group.id(),recipient.login().loginAccountId(),false);
        SecurityContextHolder.getContext().setAuthentication(service);
        assertThatThrownBy(()->authorization.recipient(service,delegated(),new IndividualRecipientRequest(login.loginAccountId(),recipient.login().loginAccountId(),group.id())))
            .isInstanceOfSatisfying(OperationAuthorizationFailure.class,failure->assertThat(failure.status()).isEqualTo(HttpStatus.FORBIDDEN));
    }
    @Test void unrelatedOrDifferentGroupRecipientCannotUseAValidBasicAccountAsMembership() {
        Actor recipient=registerActor();
        PersonalGroupService.GroupView source=personalGroups.create(asUser(login),login.loginAccountId(),"Source group",UUID.randomUUID());
        PersonalGroupService.GroupView other=personalGroups.create(asUser(login),login.loginAccountId(),"Other group",UUID.randomUUID());
        PersonalGroupService.Invitation invitation=personalGroups.invite(asUser(login),login.loginAccountId(),other.id(),recipient.login().loginAccountId(),UUID.randomUUID());
        personalGroups.respond(asUser(recipient.login()),recipient.login().loginAccountId(),invitation.id(),true);
        SecurityContextHolder.getContext().setAuthentication(service);
        assertThatThrownBy(()->authorization.recipient(service,delegated(),new IndividualRecipientRequest(login.loginAccountId(),recipient.login().loginAccountId(),source.id())))
            .isInstanceOfSatisfying(OperationAuthorizationFailure.class,failure->assertThat(failure.status()).isEqualTo(HttpStatus.FORBIDDEN));
        assertThatThrownBy(()->authorization.recipient(service,delegated(),new IndividualRecipientRequest(login.loginAccountId(),UUID.randomUUID(),source.id())))
            .isInstanceOfSatisfying(OperationAuthorizationFailure.class,failure->assertThat(failure.status()).isEqualTo(HttpStatus.FORBIDDEN));
        assertThatThrownBy(()->authorization.recipient(service,delegated(),new IndividualRecipientRequest(login.loginAccountId(),recipient.login().loginAccountId(),UUID.randomUUID())))
            .isInstanceOfSatisfying(OperationAuthorizationFailure.class,failure->assertThat(failure.status()).isEqualTo(HttpStatus.FORBIDDEN));
    }
    @Test void recipientMembershipCannotSubstituteForMissingSenderMembership() {
        Actor recipient=registerActor();
        PersonalGroupService.GroupView group=personalGroups.create(asUser(recipient.login()),recipient.login().loginAccountId(),"Recipient private group",UUID.randomUUID());
        SecurityContextHolder.getContext().setAuthentication(service);
        assertThatThrownBy(()->authorization.recipient(service,delegated(),new IndividualRecipientRequest(login.loginAccountId(),recipient.login().loginAccountId(),group.id())))
            .isInstanceOfSatisfying(OperationAuthorizationFailure.class,failure->assertThat(failure.status()).isEqualTo(HttpStatus.FORBIDDEN));
    }
    private record Actor(RegistrationCompletionResponse identity,TokenResponse login) { }
    private Actor registerActor(){
        String email=UUID.randomUUID()+"@example.test";
        RegistrationResponse pending=registration.register(new RegistrationRequest("Recipient",email,"LongStrongPassword!2026"));
        String proof=delivery.tokens.get(pending.id());registration.verify(pending.id(),new VerificationRequest(proof));
        RegistrationCompletionResponse identity=provisioning.complete(pending.id(),new RegistrationCompletionRequest(proof));
        return new Actor(identity,authentication.login(new LoginRequest(email,"LongStrongPassword!2026")));
    }
    private Jwt asUser(TokenResponse response){Jwt principal=users.decode(response.accessToken());SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(principal,List.of()));return principal;}

    private String delegated() { return "Bearer " + login.accessToken(); }
    private OperationAuthorizationRequest request(String key) { return new OperationAuthorizationRequest(key, login.loginAccountId(), "FILE", null, null); }
}

