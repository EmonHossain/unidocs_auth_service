package com.unidocs.auth.registration;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.group.api.*;
import com.unidocs.auth.group.application.*;
import com.unidocs.auth.group.domain.*;
import com.unidocs.auth.group.persistence.AcademicRepository;
import com.unidocs.auth.organization.api.*;
import com.unidocs.auth.organization.application.OrganizationService;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.application.*;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Import({RegistrationIntegrationTests.DeliveryConfiguration.class,AccountLifecycleIntegrationTests.NoticeConfiguration.class})
class GroupRulesIntegrationTests extends MySqlIntegrationTest {
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired GroupService groups;
    @Autowired GroupMembershipService memberships;
    @Autowired GroupJoinService joins;
    @Autowired GroupRuleService rules;
    @Autowired AcademicEnrollmentService academics;
    @Autowired GroupInvitationService invitations;
    @Autowired com.unidocs.auth.account.lifecycle.AccountLifecycleService lifecycle;
    @Autowired MockMvc mvc;
    @Autowired tools.jackson.databind.json.JsonMapper json;
    @MockitoSpyBean OutboxRepository outbox;
    @MockitoSpyBean java.time.Clock clock;
    private record Actor(UUID account,TokenResponse token,String email) { }
    private Actor admin,student;
    private OrganizationResponse organization;
    private UUID anchor;
    private Instant now;
    private Actor actor() {
        String email=UUID.randomUUID()+"@example.com";
        RegistrationResponse pending=registrations.register(new RegistrationRequest("Group Actor",email,"test-password-long"));
        String proof=delivery.tokens.get(pending.id());registrations.verify(pending.id(),new VerificationRequest(proof));
        RegistrationCompletionResponse identity=provisioning.complete(pending.id(),new RegistrationCompletionRequest(proof));
        return new Actor(identity.accountId(),authentication.login(new LoginRequest(email,"test-password-long")),email);
    }
    @BeforeEach void provision() {
        admin=actor();student=actor();now=Instant.now().truncatedTo(ChronoUnit.MICROS);
        organization=organizations.create(admin.token().sessionId(),admin.account(),new OrganizationRequest(admin.account(),UUID.randomUUID(),"University",
                "rules-"+UUID.randomUUID(),Organization.Type.UNIVERSITY));
        anchor=UUID.randomUUID();jdbc.update("""
            INSERT INTO organization_membership(id,organization_id,account_id,role,status,official_email,version,joined_at,created_at,updated_at)
            VALUES(?,?,?,'MEMBER','ACTIVE',?,1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))
            """,bytes(anchor),bytes(organization.id()),bytes(student.account()),student.email());
        doReturn(now).when(clock).instant();
    }
    private GroupResponse group(Group.Type type) {
        return groups.create(admin.token().sessionId(),admin.account(),organization.id(),new GroupRequest(admin.account(),UUID.randomUUID(),type.name(),type,null));
    }
    private GroupRule configure(GroupResponse group,GroupRule.Discovery discovery,GroupRule.Joining joining,UUID department,UUID semester,long version) {
        return rules.configure(admin.token().sessionId(),admin.account(),organization.id(),group.id(),new GroupRuleRequests.Configure(admin.account(),version,discovery,joining,department,semester));
    }
    private List<UUID> discovered() {
        return rules.discover(student.token().sessionId(),student.account(),organization.id(),student.account(),null,100).groups().stream().map(row->row.group().id()).toList();
    }
    private AcademicRepository.Semester semester(String code) {
        return academics.createSemester(admin.token().sessionId(),admin.account(),organization.id(),new GroupRuleRequests.Semester(admin.account(),code,now.minusSeconds(60),now.plusSeconds(86400)));
    }
    private GroupRuleRequests.Enrollment enrollment(UUID semester,long version,List<UUID> courses) {
        return new GroupRuleRequests.Enrollment(admin.account(),UUID.randomUUID(),student.account(),version,semester,courses);
    }
    private AcademicEnrollmentService.EnrollmentView replace(GroupRuleRequests.Enrollment command) {
        return academics.replace(admin.token().sessionId(),admin.account(),organization.id(),command);
    }
    private void forbidden(Runnable action) {
        assertThatThrownBy(action::run).isInstanceOf(GroupFailure.class).extracting("status").isEqualTo(HttpStatus.FORBIDDEN);
    }
    // The Phase 3 contract retires these administrator/curator routes. Positive student paths live in StudentAuthorizationIntegrationTests.
    @Test void legacyOrganizationOwnerCannotCreateInstitutionCoursesOrSemesters() {
        forbidden(()->group(Group.Type.COURSE));forbidden(()->group(Group.Type.DEPARTMENT));
        forbidden(()->semester("retired-admin-path"));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM academic_semester WHERE organization_id=?",Integer.class,bytes(organization.id()))).isZero();
    }
    @Test void neitherOwnerNorLegacyCuratorCanReplaceAnotherStudentsCourses() {
        GroupRuleRequests.Enrollment command=enrollment(UUID.randomUUID(),0,List.of());
        forbidden(()->replace(command));
        jdbc.update("INSERT INTO institute_curator(organization_id,membership_id) VALUES(?,?)",bytes(organization.id()),bytes(anchor));
        forbidden(()->academics.replace(student.token().sessionId(),student.account(),organization.id(),new GroupRuleRequests.Enrollment(student.account(),UUID.randomUUID(),student.account(),0,UUID.randomUUID(),List.of())));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM student_enrollment WHERE organization_id=?",Integer.class,bytes(organization.id()))).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_student_course WHERE organization_id=?",Integer.class,bytes(organization.id()))).isZero();
    }
    @Test void knownCourseIdentifiersDoNotReopenLegacyDiscoveryOrRuleManagement() {
        UUID course=UUID.randomUUID();
        jdbc.update("INSERT INTO iam_group(id,organization_id,name,type,status,version,created_by_account_id,creation_request_id,creation_fingerprint,created_at,updated_at) VALUES(?,?,'Legacy course','COURSE','ACTIVE',1,?,?,REPEAT('a',64),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))",bytes(course),bytes(organization.id()),bytes(admin.account()),bytes(UUID.randomUUID()));
        jdbc.update("INSERT INTO group_rule(group_id,organization_id,discovery_scope,join_rule,version) VALUES(?,?,'ORGANIZATION','COURSE_ENROLLMENT',1)",bytes(course),bytes(organization.id()));
        forbidden(()->groups.get(admin.token().sessionId(),admin.account(),admin.account(),organization.id(),course));
        forbidden(()->rules.discover(student.token().sessionId(),student.account(),organization.id(),student.account(),null,100));
        forbidden(()->rules.configure(admin.token().sessionId(),admin.account(),organization.id(),course,new GroupRuleRequests.Configure(admin.account(),1,GroupRule.Discovery.ORGANIZATION,GroupRule.Joining.OPEN,null,null)));
    }
    @Test void httpRequiresRealAuthenticationAndLegacyOwnerCannotUseNewStudentCatalog() throws Exception {
        String base="/api/v1/organizations/"+organization.id();
        mvc.perform(get(base+"/discoverable-groups").param("accountId",student.account().toString()).header("X-User-Id",student.account().toString())).andExpect(status().isUnauthorized());
        mvc.perform(get(base+"/discoverable-groups").param("accountId",student.account().toString()).header("Authorization","Bearer "+student.token().accessToken())).andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/institutes/"+organization.id()+"/workspace/courses").param("accountId",admin.account().toString()).header("Authorization","Bearer "+admin.token().accessToken())).andExpect(status().isForbidden());
    }
}