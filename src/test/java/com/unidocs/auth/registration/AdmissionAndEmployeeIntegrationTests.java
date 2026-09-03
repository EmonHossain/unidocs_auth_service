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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.TestSecurityContextHolder;
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
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
class AdmissionAndEmployeeIntegrationTests extends MySqlIntegrationTest {
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired EmployeeService employees;
    @Autowired StudentAdmissionService admissions;
    @Autowired GroupService groups;
    @Autowired MockMvc mvc;
    @MockitoBean EvidenceStorage storage;
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
        } else {
            TokenResponse token=StudentFixture.administrator(application,owner.token(),"test-password-long",result.id());
            owner=new Actor(token.loginAccountId(),token,owner.email());
        }
        return result;
    }
    EmployeeRequests.Credentials employee(OrganizationResponse org) {
        return employees.create(owner.token().sessionId(),owner.account(),org.id(),new EmployeeRequests.Create(owner.account(),UUID.randomUUID(),"Employee"));
    }
    StudentRequests.View apply(OrganizationResponse org,Actor student,String email,StudentEvidence evidence) {
        return admissions.apply(student.token().sessionId(),student.account(),org.id(),new StudentRequests.Apply(student.account(),email,"university-password-long"),evidence);
    }
    StudentRequests.View verify(OrganizationResponse org,Actor student,StudentRequests.View view) {
        return admissions.verify(student.token().sessionId(),student.account(),org.id(),view.id(),new StudentRequests.Verify(student.account(),delivery.tokens.get(view.id())));
    }
    @Test void employeeNeedsNoEmailButMustReplaceTemporaryPasswordBeforeLoginAndResetRevokesGrant() {
        OrganizationResponse org=org(Organization.Type.COMPANY);EmployeeRequests.Credentials employee=employee(org);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_contact c JOIN user_account a ON a.user_id=c.user_id WHERE a.id=?",Integer.class,bytes(employee.accountId()))).isZero();
        assertThatThrownBy(()->authentication.loginAccount(employee.accountId(),new AccountLoginRequest(employee.temporaryPassword()))).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(()->employees.login(new EmployeeRequests.Login(employee.username(),employee.temporaryPassword(),null))).isInstanceOf(AuthenticationFailure.class);
        TokenResponse token=employees.login(new EmployeeRequests.Login(employee.username(),employee.temporaryPassword(),"permanent-password-long"));
        assertThat(organizations.get(token.sessionId(),employee.accountId(),employee.accountId(),org.id()).role().name()).isEqualTo("MEMBER");
        assertThat(jdbc.queryForObject("SELECT auth_method FROM session_account_grant WHERE session_id=?",String.class,bytes(token.sessionId()))).isEqualTo("LOGIN");
        assertThatThrownBy(()->employees.login(new EmployeeRequests.Login(employee.username(),employee.temporaryPassword(),"another-password-long"))).isInstanceOf(AuthenticationFailure.class);
        assertThat(employees.login(new EmployeeRequests.Login(employee.username(),"permanent-password-long",null))).isNotNull();
        EmployeeRequests.Credentials reset=employees.reset(owner.token().sessionId(),owner.account(),org.id(),employee.accountId(),new EmployeeRequests.Reset(owner.account(),"test-password-long"));
        assertThat(reset.temporaryPassword()).isNotEqualTo(employee.temporaryPassword());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant WHERE account_id=? AND status='ACTIVE'",Integer.class,bytes(employee.accountId()))).isZero();
        assertThatThrownBy(()->employees.login(new EmployeeRequests.Login(employee.username(),"permanent-password-long",null))).isInstanceOf(AuthenticationFailure.class);
        assertThat(employees.login(new EmployeeRequests.Login(reset.username(),reset.temporaryPassword(),"second-password-long"))).isNotNull();
        List<String> payloads=jdbc.queryForList("SELECT payload FROM outbox_event",String.class);
        assertThat(payloads.toString()).doesNotContain(employee.temporaryPassword(),"permanent-password-long",employee.username());
    }
    @Test void temporaryCredentialsLockAfterFiveFailuresAndCannotProvisionUniversityEmployee() {
        OrganizationResponse org=org(Organization.Type.COMPANY);EmployeeRequests.Credentials employee=employee(org);
        for(int i=0;i<5;i++)assertThatThrownBy(()->employees.login(new EmployeeRequests.Login(employee.username(),"wrong-password","permanent-password-long"))).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(()->employees.login(new EmployeeRequests.Login(employee.username(),employee.temporaryPassword(),"permanent-password-long"))).isInstanceOf(AuthenticationFailure.class);
        assertThat(jdbc.queryForObject("SELECT attempts FROM employee_activation WHERE account_id=?",Integer.class,bytes(employee.accountId()))).isEqualTo(5);
        OrganizationResponse university=org(Organization.Type.UNIVERSITY);
        assertThatThrownBy(()->employee(university)).isInstanceOf(OrganizationFailure.class);
    }
    @Test void employeeCreationIsScopedAndDoesNotReplayCredentials() throws Exception {
        OrganizationResponse org=org(Organization.Type.COMPANY);Actor outsider=actor();
        EmployeeRequests.Create command=new EmployeeRequests.Create(owner.account(),UUID.randomUUID(),"Employee");
        employees.create(owner.token().sessionId(),owner.account(),org.id(),command);
        assertThatThrownBy(()->employees.create(owner.token().sessionId(),owner.account(),org.id(),command)).isInstanceOf(OrganizationFailure.class);
        assertThatThrownBy(()->employees.create(outsider.token().sessionId(),outsider.account(),org.id(),new EmployeeRequests.Create(outsider.account(),UUID.randomUUID(),"Denied"))).isInstanceOf(OrganizationFailure.class);
        SecurityContextHolder.clearContext();
        TestSecurityContextHolder.clearContext();
        mvc.perform(post("/api/v1/organizations/"+org.id()+"/employees").contentType(MediaType.APPLICATION_JSON)
                .content("{\"adminAccountId\":\""+owner.account()+"\",\"requestId\":\""+UUID.randomUUID()+"\",\"displayName\":\"No token\"}"))
                .andExpect(status().isUnauthorized());
    }
    @Test void institutionMailboxProofCreatesUniversityAccountButDoesNotGrantCoursesOrUnlockNewAccount() {
        OrganizationResponse org=org(Organization.Type.UNIVERSITY);Actor student=actor();
        jdbc.update("INSERT INTO institute_email_domain(organization_id,domain) VALUES(?,'students.example.edu')",bytes(org.id()));
        StudentRequests.View pending=apply(org,student,"learner@students.example.edu",null);
        assertThat(pending.status()).isEqualTo("EMAIL_PENDING");assertThat(pending.studentAccountId()).isNull();
        assertThat(delivery.tokens.get(pending.id())).matches("[0-9]{6}");
        assertThat(jdbc.queryForObject("SELECT TIMESTAMPDIFF(SECOND,created_at,code_expires_at) FROM student_admission WHERE id=?",Integer.class,bytes(pending.id()))).isEqualTo(300);
        StudentRequests.View approved=verify(org,student,pending);assertThat(approved.status()).isEqualTo("APPROVED");
        assertThat(verify(org,student,pending)).isEqualTo(approved);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_student_state WHERE organization_id=? AND account_id=?",Integer.class,bytes(org.id()),bytes(approved.studentAccountId()))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT type FROM user_account WHERE id=?",String.class,bytes(approved.studentAccountId()))).isEqualTo("UNIVERSITY");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM group_membership WHERE account_id=?",Integer.class,bytes(approved.studentAccountId()))).isZero();
        assertThatThrownBy(()->organizations.get(student.token().sessionId(),student.account(),approved.studentAccountId(),org.id())).isInstanceOf(OrganizationFailure.class);
        assertThat(authentication.loginAccount(approved.studentAccountId(),new AccountLoginRequest("university-password-long"))).isNotNull();
        verifyNoInteractions(storage);
    }
    @Test void personalEmailEvidenceRemainsPendingUntilCuratorReviewsAndNetworkCallsAreOutsideTransactions() {
        OrganizationResponse org=org(Organization.Type.UNIVERSITY);Actor student=actor();
        StudentEvidence evidence=new StudentEvidence("%PDF-1.7 evidence".getBytes(StandardCharsets.US_ASCII),"application/pdf");
        doAnswer(call->{assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();return null;}).when(storage).put(anyString(),any(StudentEvidence.class));
        StudentRequests.View pending=apply(org,student,student.email(),evidence);StudentRequests.View confirmed=verify(org,student,pending);
        assertThat(confirmed.status()).isEqualTo("PENDING_REVIEW");assertThat(confirmed.studentAccountId()).isNull();
        assertThat(admissions.list(owner.token().sessionId(),owner.account(),org.id(),owner.account(),null,10).admissions()).hasSize(1);
        when(storage.get(anyString())).thenAnswer(call->{assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();return evidence.bytes();});
        assertThat(admissions.evidence(owner.token().sessionId(),owner.account(),org.id(),pending.id(),owner.account()).bytes()).isEqualTo(evidence.bytes());
        assertThatThrownBy(()->admissions.review(student.token().sessionId(),student.account(),org.id(),pending.id(),new StudentRequests.Review(student.account(),true,"Self review"))).isInstanceOf(OrganizationFailure.class);
        StudentRequests.View approved=admissions.review(owner.token().sessionId(),owner.account(),org.id(),pending.id(),new StudentRequests.Review(owner.account(),true,"Enrollment document confirmed"));
        assertThat(approved.status()).isEqualTo("APPROVED");assertThat(approved.studentAccountId()).isNotNull();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM admission_evidence_deletion",Integer.class)).isEqualTo(1);
        assertThatThrownBy(()->admissions.evidence(owner.token().sessionId(),owner.account(),org.id(),pending.id(),owner.account())).isInstanceOf(OrganizationFailure.class);
    }
    @Test void expiredAndWrongCodesDoNotGrantInstitutionAccessAndOutsidersCannotReview() throws Exception {
        OrganizationResponse org=org(Organization.Type.UNIVERSITY);Actor student=actor();
        StudentEvidence evidence=new StudentEvidence("%PDF-1.7 evidence".getBytes(StandardCharsets.US_ASCII),"application/pdf");
        StudentRequests.View pending=apply(org,student,student.email(),evidence);
        for(int i=0;i<5;i++)assertThatThrownBy(()->admissions.verify(student.token().sessionId(),student.account(),org.id(),pending.id(),new StudentRequests.Verify(student.account(),"wrong"))).isInstanceOf(OrganizationFailure.class);
        assertThat(admissions.get(student.token().sessionId(),student.account(),org.id(),pending.id(),student.account()).status()).isEqualTo("FAILED");
        StudentRequests.View expired=apply(org,student,student.email(),evidence);
        jdbc.update("UPDATE student_admission SET code_expires_at=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND WHERE id=?",bytes(expired.id()));
        assertThatThrownBy(()->verify(org,student,expired)).isInstanceOf(OrganizationFailure.class);
        assertThat(admissions.get(student.token().sessionId(),student.account(),org.id(),expired.id(),student.account()).status()).isEqualTo("EXPIRED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM admission_evidence_deletion",Integer.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM student_admission WHERE id IN (?,?) AND password_hash='CONSUMED' AND code_hash='CONSUMED'",Integer.class,bytes(pending.id()),bytes(expired.id()))).isEqualTo(2);
        mvc.perform(get("/api/v1/institutes/"+org.id()+"/student-admissions").param("accountId",student.account().toString()).header("Authorization","Bearer "+student.token().accessToken())).andExpect(status().isForbidden());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM organization_membership WHERE organization_id=? AND status='ACTIVE'",Integer.class,bytes(org.id()))).isEqualTo(2);
    }
    @Test void legacyCampusCuratorDelegationCannotGrantStudentAdministrationOrCourseAssignment() {
        OrganizationResponse org=org(Organization.Type.UNIVERSITY);Actor volunteer=actor();UUID membership=UUID.randomUUID();
        jdbc.update("INSERT INTO organization_membership(id,organization_id,account_id,role,status,official_email,version,joined_at,created_at,updated_at) VALUES(?,?,?,'MEMBER','ACTIVE',?,1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))",bytes(membership),bytes(org.id()),bytes(volunteer.account()),volunteer.email());
        assertThatThrownBy(()->admissions.assignCurator(owner.token().sessionId(),owner.account(),org.id(),new StudentRequests.Curator(owner.account(),membership,true))).isInstanceOf(OrganizationFailure.class);
        jdbc.update("INSERT INTO institute_curator(organization_id,membership_id) VALUES(?,?)",bytes(org.id()),bytes(membership));
        assertThatThrownBy(()->admissions.list(volunteer.token().sessionId(),volunteer.account(),org.id(),volunteer.account(),null,10)).isInstanceOf(OrganizationFailure.class);
        assertThatThrownBy(()->groups.create(volunteer.token().sessionId(),volunteer.account(),org.id(),new GroupRequest(volunteer.account(),UUID.randomUUID(),"Math101",Group.Type.COURSE,null))).isInstanceOf(GroupFailure.class);
        assertThatThrownBy(()->groups.create(volunteer.token().sessionId(),volunteer.account(),org.id(),new GroupRequest(volunteer.account(),UUID.randomUUID(),"Private",Group.Type.TEAM,null))).isInstanceOf(GroupFailure.class);
        OrganizationResponse other=org(Organization.Type.UNIVERSITY);
        assertThatThrownBy(()->admissions.list(volunteer.token().sessionId(),volunteer.account(),other.id(),volunteer.account(),null,10)).isInstanceOf(OrganizationFailure.class);
        assertThatThrownBy(()->admissions.assignCurator(owner.token().sessionId(),owner.account(),org.id(),new StudentRequests.Curator(owner.account(),membership,false))).isInstanceOf(OrganizationFailure.class);
        assertThatThrownBy(()->admissions.list(volunteer.token().sessionId(),volunteer.account(),org.id(),volunteer.account(),null,10)).isInstanceOf(OrganizationFailure.class);
    }
}
