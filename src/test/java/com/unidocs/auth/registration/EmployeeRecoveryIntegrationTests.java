package com.unidocs.auth.registration;
import java.util.UUID;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.registration.application.*;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.student.*;
import com.unidocs.auth.organization.application.*;
import com.unidocs.auth.organization.api.*;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.organization.employee.*;
import com.unidocs.auth.organization.employee.recovery.*;
import com.unidocs.auth.authentication.application.*;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.group.application.*;
import com.unidocs.auth.group.api.*;
import com.unidocs.auth.group.domain.Group;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@SpringBootTest
@AutoConfigureMockMvc
@Import({RegistrationIntegrationTests.DeliveryConfiguration.class,InvitationIntegrationTests.DeliveryConfiguration.class})
class EmployeeRecoveryIntegrationTests extends MySqlIntegrationTest {
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired EmployeeService employees;
    @Autowired com.unidocs.auth.organization.employee.recovery.EmployeeRecoveryService recoveries;
    @Autowired GroupService groups;
    @Autowired InvitationService invitations;
    @Autowired OrganizationAccountService organizationAccounts;
    @Autowired InvitationIntegrationTests.CapturingInvitations invitationMail;
    @Autowired MockMvc mvc;
    @MockitoBean EvidenceStorage storage;
    @MockitoBean com.unidocs.auth.credential.recovery.email.EmailRecoveryDelivery emailRecoveryDelivery;
    @Autowired com.unidocs.auth.credential.recovery.email.EmailPasswordRecoveryService emailRecoveries;
    record Actor(UUID account,TokenResponse token,String email) { }
    Actor owner;
    Actor personalOwner;
    @Autowired org.springframework.context.ApplicationContext application;
    @BeforeEach void owner() { owner=actor();personalOwner=owner; }
    Actor actor() {
        String email=UUID.randomUUID()+"@example.com";
        RegistrationResponse pending=registrations.register(new RegistrationRequest("Test person",email,"test-password-long"));
        String code=delivery.tokens.get(pending.id());registrations.verify(pending.id(),new VerificationRequest(code));
        RegistrationCompletionResponse identity=provisioning.complete(pending.id(),new RegistrationCompletionRequest(code));
        return new Actor(identity.accountId(),authentication.login(new LoginRequest(email,"test-password-long")),email);
    }
    OrganizationResponse org(Organization.Type type) {
        owner=personalOwner;
        OrganizationResponse result=organizations.create(owner.token().sessionId(),owner.account(),new OrganizationRequest(owner.account(),UUID.randomUUID(),"Test institution","org-"+UUID.randomUUID(),type));
        if(type!=Organization.Type.UNIVERSITY) {
            TokenResponse token=ProfessionalFixture.administrator(application,owner.token(),"test-password-long",result.id());
            owner=new Actor(token.loginAccountId(),token,owner.email());
        }
        return result;
    }
    EmployeeRequests.Credentials employee(OrganizationResponse org) {
        return employees.create(owner.token().sessionId(),owner.account(),org.id(),new EmployeeRequests.Create(owner.account(),UUID.randomUUID(),"Employee"));
    }
    @Test void employeeRequestDoesNotDisablePasswordAndScopedAdminIssuesSingleUsePin() throws Exception {
        OrganizationResponse org=org(Organization.Type.COMPANY);EmployeeRequests.Credentials employee=employee(org);
        TokenResponse old=employees.login(new EmployeeRequests.Login(employee.username(),employee.temporaryPassword(),"permanent-password-long"));
        UUID request=UUID.randomUUID();recoveries.request(new EmployeeRecoveryRequests.Forgot(employee.username(),request));
        assertThat(employees.login(new EmployeeRequests.Login(employee.username(),"permanent-password-long",null))).isNotNull();
        assertThat(recoveries.list(owner.token().sessionId(),owner.account(),org.id(),owner.account(),null,20)).hasSize(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM account_security_notice WHERE account_id=? AND code='EMPLOYEE_PASSWORD_RECOVERY_REQUESTED'",Integer.class,bytes(owner.account()))).isEqualTo(1);
        Actor outsider=actor();OrganizationResponse other=organizations.create(outsider.token().sessionId(),outsider.account(),new OrganizationRequest(outsider.account(),UUID.randomUUID(),"Other company","other-"+UUID.randomUUID(),Organization.Type.COMPANY));
        mvc.perform(post("/api/v1/organizations/"+org.id()+"/password-recovery-requests/"+request+"/reset").header("Authorization","Bearer "+outsider.token().accessToken()).contentType(MediaType.APPLICATION_JSON).content("{\"adminAccountId\":\""+outsider.account()+"\",\"identityVerified\":true,\"password\":\"test-password-long\"}")).andExpect(status().isForbidden());
        assertThatThrownBy(()->recoveries.issue(owner.token().sessionId(),owner.account(),org.id(),request,new EmployeeRecoveryRequests.Issue(owner.account(),false,"test-password-long"))).isInstanceOf(OrganizationFailure.class);
        EmployeeRecoveryRequests.Pin pin=recoveries.issue(owner.token().sessionId(),owner.account(),org.id(),request,new EmployeeRecoveryRequests.Issue(owner.account(),true,"test-password-long"));
        assertThat(pin.pin()).matches("[0-9]{6}");
        assertThat(jdbc.queryForObject("SELECT pin_hash FROM employee_password_recovery WHERE id=?",String.class,bytes(request))).doesNotContain(pin.pin());
        assertThat(jdbc.queryForObject("SELECT status FROM user_session WHERE id=?",String.class,bytes(old.sessionId()))).isEqualTo("REVOKED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_refresh_token WHERE session_id=? AND revoked_at IS NULL",Integer.class,bytes(old.sessionId()))).isZero();
        assertThatThrownBy(()->authentication.refresh(new RefreshRequest(old.refreshToken()))).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(()->employees.login(new EmployeeRequests.Login(employee.username(),"permanent-password-long",null))).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(()->employees.login(new EmployeeRequests.Login(employee.username(),pin.pin(),"attacker-password-long"))).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(()->authentication.loginAccount(employee.accountId(),new AccountLoginRequest(pin.pin()))).isInstanceOf(AuthenticationFailure.class);
        mvc.perform(get("/api/v1/organizations/"+org.id()).param("accountId",employee.accountId().toString()).header("Authorization","Bearer "+old.accessToken())).andExpect(status().isUnauthorized());
        jdbc.update("UPDATE employee_password_recovery SET issued_at=UTC_TIMESTAMP(6)-INTERVAL 1 YEAR WHERE id=?",bytes(request));
        recoveries.reset(new EmployeeRecoveryRequests.Reset(employee.username(),request,pin.pin(),"new-permanent-password"));
        assertThat(employees.login(new EmployeeRequests.Login(employee.username(),"new-permanent-password",null))).isNotNull();
        assertThatThrownBy(()->recoveries.reset(new EmployeeRecoveryRequests.Reset(employee.username(),request,pin.pin(),"another-password-long"))).isInstanceOf(AuthenticationFailure.class);
        assertThat(jdbc.queryForObject("SELECT pin_hash FROM employee_password_recovery WHERE id=?",String.class,bytes(request))).isNull();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM account_security_notice WHERE account_id=?",Integer.class,bytes(employee.accountId()))).isEqualTo(1);
        assertThat(jdbc.queryForList("SELECT payload FROM outbox_event",String.class).toString()).doesNotContain(pin.pin(),"new-permanent-password");
    }
    @Test void fiveWrongPinsLockAndAdministratorCanReissueBoundToCurrentCredentialVersion() {
        OrganizationResponse org=org(Organization.Type.COMPANY);EmployeeRequests.Credentials employee=employee(org);
        employees.login(new EmployeeRequests.Login(employee.username(),employee.temporaryPassword(),"permanent-password-long"));
        UUID request=UUID.randomUUID();recoveries.request(new EmployeeRecoveryRequests.Forgot(employee.username(),request));
        EmployeeRecoveryRequests.Pin first=recoveries.issue(owner.token().sessionId(),owner.account(),org.id(),request,new EmployeeRecoveryRequests.Issue(owner.account(),true,"test-password-long"));
        String wrong=first.pin().equals("000000")?"000001":"000000";
        for(int i=0;i<5;i++)assertThatThrownBy(()->recoveries.reset(new EmployeeRecoveryRequests.Reset(employee.username(),request,wrong,"new-password-long"))).isInstanceOf(AuthenticationFailure.class);
        assertThat(jdbc.queryForObject("SELECT status FROM employee_password_recovery WHERE id=?",String.class,bytes(request))).isEqualTo("LOCKED");
        assertThatThrownBy(()->recoveries.reset(new EmployeeRecoveryRequests.Reset(employee.username(),request,first.pin(),"new-password-long"))).isInstanceOf(AuthenticationFailure.class);
        EmployeeRecoveryRequests.Pin next=recoveries.issue(owner.token().sessionId(),owner.account(),org.id(),request,new EmployeeRecoveryRequests.Issue(owner.account(),true,"test-password-long"));
        recoveries.reset(new EmployeeRecoveryRequests.Reset(employee.username(),request,next.pin(),"new-password-long"));
        assertThat(employees.login(new EmployeeRequests.Login(employee.username(),"new-password-long",null))).isNotNull();
    }
    @Test void unknownAndRepeatedRequestsAreGenericAndDoNotFloodInbox() throws Exception {
        mvc.perform(post("/api/v1/auth/employee-forgot-password").contentType(MediaType.APPLICATION_JSON).content("{\"username\":\"unknown\",\"requestId\":\""+UUID.randomUUID()+"\"}")).andExpect(status().isAccepted()).andExpect(header().string("Cache-Control","no-store"));
        OrganizationResponse org=org(Organization.Type.COMPANY);EmployeeRequests.Credentials employee=employee(org);
        UUID request=UUID.randomUUID();recoveries.request(new EmployeeRecoveryRequests.Forgot(employee.username(),request));
        recoveries.request(new EmployeeRecoveryRequests.Forgot(employee.username(),UUID.randomUUID()));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM employee_password_recovery",Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT status FROM employee_activation WHERE account_id=?",String.class,bytes(employee.accountId()))).isEqualTo("PENDING");
    }
    @Test void anotherAdministrativeCredentialResetSupersedesRecoveryPin() {
        OrganizationResponse org=org(Organization.Type.COMPANY);EmployeeRequests.Credentials employee=employee(org);
        UUID request=UUID.randomUUID();recoveries.request(new EmployeeRecoveryRequests.Forgot(employee.username(),request));
        EmployeeRecoveryRequests.Pin pin=recoveries.issue(owner.token().sessionId(),owner.account(),org.id(),request,new EmployeeRecoveryRequests.Issue(owner.account(),true,"test-password-long"));
        EmployeeRequests.Credentials changed=employees.reset(owner.token().sessionId(),owner.account(),org.id(),employee.accountId(),new EmployeeRequests.Reset(owner.account(),"test-password-long"));
        assertThatThrownBy(()->recoveries.reset(new EmployeeRecoveryRequests.Reset(employee.username(),request,pin.pin(),"new-password-long"))).isInstanceOf(AuthenticationFailure.class);
        assertThat(employees.login(new EmployeeRequests.Login(changed.username(),changed.temporaryPassword(),"new-password-long"))).isNotNull();
    }
    @Test void organizationRevocationPreventsPinUse() {
        OrganizationResponse org=org(Organization.Type.COMPANY);EmployeeRequests.Credentials employee=employee(org);
        UUID request=UUID.randomUUID();recoveries.request(new EmployeeRecoveryRequests.Forgot(employee.username(),request));
        EmployeeRecoveryRequests.Pin pin=recoveries.issue(owner.token().sessionId(),owner.account(),org.id(),request,new EmployeeRecoveryRequests.Issue(owner.account(),true,"test-password-long"));
        jdbc.update("UPDATE organization_membership SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6),revoked_by=?,version=version+1,updated_at=UTC_TIMESTAMP(6) WHERE account_id=?",bytes(owner.account()),bytes(employee.accountId()));
        assertThatThrownBy(()->recoveries.reset(new EmployeeRecoveryRequests.Reset(employee.username(),request,pin.pin(),"new-password-long"))).isInstanceOf(AuthenticationFailure.class);
    }
    @Test void EmployeeAdministratorCannotApproveOwnRecoveryRequest() {
        OrganizationResponse org=org(Organization.Type.COMPANY);EmployeeRequests.Credentials employee=employee(org);
        TokenResponse token=employees.login(new EmployeeRequests.Login(employee.username(),employee.temporaryPassword(),"permanent-password-long"));
        jdbc.update("UPDATE organization_membership SET role='ADMIN' WHERE account_id=?",bytes(employee.accountId()));
        UUID request=UUID.randomUUID();recoveries.request(new EmployeeRecoveryRequests.Forgot(employee.username(),request));
        assertThatThrownBy(()->recoveries.issue(token.sessionId(),employee.accountId(),org.id(),request,new EmployeeRecoveryRequests.Issue(employee.accountId(),true,"permanent-password-long"))).isInstanceOf(OrganizationFailure.class);
        assertThat(jdbc.queryForObject("SELECT status FROM employee_password_recovery WHERE id=?",String.class,bytes(request))).isEqualTo("REQUESTED");
        assertThatThrownBy(()->employees.reset(token.sessionId(),employee.accountId(),org.id(),employee.accountId(),new EmployeeRequests.Reset(employee.accountId(),"permanent-password-long"))).isInstanceOf(OrganizationFailure.class);
    }

    @Test void AdministratorCannotTakeOverOrganizationOwnerThroughRecovery() {
        OrganizationResponse org=org(Organization.Type.COMPANY);EmployeeRequests.Credentials employee=employee(org);
        employees.login(new EmployeeRequests.Login(employee.username(),employee.temporaryPassword(),"permanent-password-long"));
        jdbc.update("UPDATE organization_membership SET role='OWNER' WHERE account_id=?",bytes(employee.accountId()));
        jdbc.update("UPDATE organization_membership SET role='ADMIN' WHERE organization_id=? AND account_id=?",bytes(org.id()),bytes(owner.account()));
        UUID request=UUID.randomUUID();recoveries.request(new EmployeeRecoveryRequests.Forgot(employee.username(),request));
        assertThatThrownBy(()->recoveries.issue(owner.token().sessionId(),owner.account(),org.id(),request,new EmployeeRecoveryRequests.Issue(owner.account(),true,"test-password-long"))).isInstanceOf(OrganizationFailure.class);
        assertThatThrownBy(()->employees.reset(owner.token().sessionId(),owner.account(),org.id(),employee.accountId(),new EmployeeRequests.Reset(owner.account(),"test-password-long"))).isInstanceOf(OrganizationFailure.class);
        assertThat(employees.login(new EmployeeRequests.Login(employee.username(),"permanent-password-long",null))).isNotNull();
    }

    @Test void LegacyOrganizationAccountRecoversByCanonicalAccountIdWithoutEmailBypass() {
        OrganizationResponse org=org(Organization.Type.COMPANY);Actor recipient=actor();
        InvitationResponse invitation=invitations.issue(owner.token().sessionId(),owner.account(),org.id(),new InvitationRequest(owner.account(),recipient.email()));
        OrganizationAccountResponse legacy=organizationAccounts.provision(recipient.token().sessionId(),recipient.account(),org.id(),invitation.id(),
            new OrganizationAccountRequest(recipient.account(),invitationMail.proofs.get(invitation.id()),"Legacy employee","legacy-password-long"));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM employee_activation WHERE account_id=?",Integer.class,bytes(legacy.accountId()))).isZero();
        emailRecoveries.forgot(new com.unidocs.auth.credential.recovery.email.EmailRecoveryRequests.Forgot(recipient.email(),legacy.accountId()));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM email_password_recovery WHERE account_id=?",Integer.class,bytes(legacy.accountId()))).isZero();
        verifyNoInteractions(emailRecoveryDelivery);
        UUID request=UUID.randomUUID();recoveries.request(new EmployeeRecoveryRequests.Forgot(legacy.accountId().toString(),request));
        assertThat(authentication.loginAccount(legacy.accountId(),new AccountLoginRequest("legacy-password-long"))).isNotNull();
        assertThat(jdbc.queryForObject("SELECT status FROM employee_activation WHERE account_id=?",String.class,bytes(legacy.accountId()))).isEqualTo("ACTIVATED");
        EmployeeRecoveryRequests.Pin pin=recoveries.issue(owner.token().sessionId(),owner.account(),org.id(),request,new EmployeeRecoveryRequests.Issue(owner.account(),true,"test-password-long"));
        recoveries.reset(new EmployeeRecoveryRequests.Reset(legacy.accountId().toString(),request,pin.pin(),"recovered-password-long"));
        assertThat(employees.login(new EmployeeRequests.Login(legacy.accountId().toString(),"recovered-password-long",null))).isNotNull();
        UUID personalRequest=UUID.randomUUID();recoveries.request(new EmployeeRecoveryRequests.Forgot(recipient.account().toString(),personalRequest));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM employee_password_recovery WHERE id=?",Integer.class,bytes(personalRequest))).isZero();
    }

    @Test void administratorPasswordFailuresCommitAndBlockBothCredentialResetPaths() {
        OrganizationResponse org=org(Organization.Type.COMPANY);
        EmployeeRequests.Credentials employee=employee(org);
        UUID request=UUID.randomUUID();
        recoveries.request(new EmployeeRecoveryRequests.Forgot(employee.username(),request));
        long version=jdbc.queryForObject("SELECT credential_version FROM login_identity WHERE account_id=?",Long.class,bytes(employee.accountId()));
        for(int attempt=0;attempt<5;attempt++) {
            assertThatThrownBy(()->employees.reset(owner.token().sessionId(),owner.account(),org.id(),employee.accountId(),
                new EmployeeRequests.Reset(owner.account(),"wrong-password-long"))).isInstanceOf(OrganizationFailure.class);
        }
        assertThat(jdbc.queryForObject("SELECT lifecycle_attempts FROM login_identity WHERE account_id=?",Integer.class,bytes(owner.account()))).isEqualTo(5);
        assertThatThrownBy(()->recoveries.issue(owner.token().sessionId(),owner.account(),org.id(),request,
            new EmployeeRecoveryRequests.Issue(owner.account(),true,"test-password-long"))).isInstanceOf(OrganizationFailure.class);
        assertThat(jdbc.queryForObject("SELECT status FROM employee_password_recovery WHERE id=?",String.class,bytes(request))).isEqualTo("REQUESTED");
        assertThat(jdbc.queryForObject("SELECT credential_version FROM login_identity WHERE account_id=?",Long.class,bytes(employee.accountId()))).isEqualTo(version);
        jdbc.update("UPDATE login_identity SET lifecycle_locked_until=DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 SECOND) WHERE account_id=?",bytes(owner.account()));
        assertThat(recoveries.issue(owner.token().sessionId(),owner.account(),org.id(),request,
            new EmployeeRecoveryRequests.Issue(owner.account(),true,"test-password-long")).pin()).matches("[0-9]{6}");
        assertThat(jdbc.queryForObject("SELECT lifecycle_attempts FROM login_identity WHERE account_id=?",Integer.class,bytes(owner.account()))).isZero();
    }

    @Test void recoveryPinIssuanceRequiresPasswordAtHttpBoundary() throws Exception {
        OrganizationResponse org=org(Organization.Type.COMPANY);
        EmployeeRequests.Credentials employee=employee(org);
        UUID request=UUID.randomUUID();
        recoveries.request(new EmployeeRecoveryRequests.Forgot(employee.username(),request));
        mvc.perform(post("/api/v1/organizations/"+org.id()+"/password-recovery-requests/"+request+"/reset")
            .header("Authorization","Bearer "+owner.token().accessToken()).contentType(MediaType.APPLICATION_JSON)
            .content("{\"adminAccountId\":\""+owner.account()+"\",\"identityVerified\":true}"))
            .andExpect(status().isBadRequest());
        assertThat(jdbc.queryForObject("SELECT status FROM employee_password_recovery WHERE id=?",String.class,bytes(request))).isEqualTo("REQUESTED");
    }

}
