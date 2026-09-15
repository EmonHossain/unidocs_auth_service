package com.unidocs.auth.registration;

import java.time.Instant;
import java.util.UUID;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authentication.api.LoginRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.group.api.*;
import com.unidocs.auth.group.application.*;
import com.unidocs.auth.group.domain.Group;
import com.unidocs.auth.organization.api.*;
import com.unidocs.auth.organization.application.*;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.organization.employee.EmployeeRequests;
import com.unidocs.auth.organization.employee.EmployeeService;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.application.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;

/** Real issued sessions; code is prepared for the separate validation stage, not claimed as executed. */
@SpringBootTest
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
class ProfessionalAdmissionIntegrationTests extends MySqlIntegrationTest {
    @Autowired ApplicationContext application;
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired GroupService groups;
    @Autowired GroupRuleService rules;
    @Autowired GroupJoinService joins;
    @Autowired GroupMembershipService memberships;
    @Autowired InvitationService invitations;
    @Autowired EmployeeService employees;
    private TokenResponse personal,administrator,employee;
    private UUID organization,team,account;
    @BeforeEach void fixture() {
        String email=UUID.randomUUID()+"@example.com";
        RegistrationResponse pending=registrations.register(new RegistrationRequest("Professional owner",email,"test-password-long"));
        String proof=delivery.tokens.get(pending.id());registrations.verify(pending.id(),new VerificationRequest(proof));
        provisioning.complete(pending.id(),new RegistrationCompletionRequest(proof));personal=authentication.login(new LoginRequest(email,"test-password-long"));
        OrganizationResponse created=organizations.create(personal.sessionId(),personal.loginAccountId(),new OrganizationRequest(personal.loginAccountId(),UUID.randomUUID(),"Professional","professional-"+UUID.randomUUID(),Organization.Type.COMPANY));
        organization=created.id();administrator=ProfessionalFixture.administrator(application,personal,"test-password-long",organization);
        team=groups.create(administrator.sessionId(),administrator.loginAccountId(),organization,new GroupRequest(administrator.loginAccountId(),UUID.randomUUID(),"Team",Group.Type.TEAM,null)).id();
        EmployeeRequests.Credentials createdEmployee=employees.create(administrator.sessionId(),administrator.loginAccountId(),organization,new EmployeeRequests.Create(administrator.loginAccountId(),UUID.randomUUID(),"Employee"));
        account=createdEmployee.accountId();employee=employees.login(new EmployeeRequests.Login(createdEmployee.username(),createdEmployee.temporaryPassword(),"permanent-password-long"));
    }
    @Test void employeeCannotSelfJoinRequestApprovalOrUseExternalOrganizationInvitations() {
        assertThatThrownBy(()->rules.join(employee.sessionId(),employee.loginAccountId(),organization,team,new GroupRuleRequests.Join(account,UUID.randomUUID()))).isInstanceOf(GroupFailure.class);
        assertThatThrownBy(()->joins.submit(employee.sessionId(),employee.loginAccountId(),organization,team,new GroupJoinRequests.Submit(account,UUID.randomUUID(),"MEMBER","Employee self-joining must be denied"))).isInstanceOf(GroupFailure.class);
        assertThatThrownBy(()->invitations.issue(administrator.sessionId(),administrator.loginAccountId(),organization,new InvitationRequest(administrator.loginAccountId(),"external@example.com"))).isInstanceOf(OrganizationFailure.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM group_membership WHERE account_id=? AND group_id=?",Integer.class,bytes(account),bytes(team))).isZero();
    }
    @Test void administratorAssignsEmployeeWithoutTurningNavigationRolesIntoCapabilities() {
        GroupMembershipResponse result=memberships.assign(administrator.sessionId(),administrator.loginAccountId(),organization,team,
                new GroupAssignmentRequest(administrator.loginAccountId(),UUID.randomUUID(),account,"label-only",Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MICROS),null));
        assertThat(result.effective()).isTrue();
        assertThatThrownBy(()->memberships.assign(employee.sessionId(),employee.loginAccountId(),organization,team,
                new GroupAssignmentRequest(account,UUID.randomUUID(),administrator.loginAccountId(),"OWNER",Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MICROS),null))).isInstanceOf(GroupFailure.class);
    }
    @Test void reconciliationIsRetrySafeAndLeavesPersonalNavigationAndSessionsIntact() {
        TokenResponse repeated=ProfessionalFixture.administrator(application,personal,"test-password-long",organization);
        assertThat(repeated.loginAccountId()).isEqualTo(administrator.loginAccountId());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_professional_reconciliation WHERE organization_id=? AND source_account_id=?",Integer.class,bytes(organization),bytes(personal.loginAccountId()))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT type FROM user_account WHERE id=?",String.class,bytes(personal.loginAccountId()))).isEqualTo("PERSONAL");
        assertThat(jdbc.queryForObject("SELECT status FROM user_session WHERE id=?",String.class,bytes(personal.sessionId()))).isEqualTo("ACTIVE");
        assertThatThrownBy(()->groups.list(personal.sessionId(),personal.loginAccountId(),personal.loginAccountId(),organization,null,10)).isInstanceOf(GroupFailure.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE aggregate_id=? AND event_type='PROFESSIONAL_ACCOUNT_RECONCILED'",Integer.class,bytes(organization))).isEqualTo(1);
    }
}
