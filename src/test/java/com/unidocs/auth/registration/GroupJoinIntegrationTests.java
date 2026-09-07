package com.unidocs.auth.registration;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authentication.api.*;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.group.api.*;
import com.unidocs.auth.group.application.*;
import com.unidocs.auth.group.domain.*;
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
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
class GroupJoinIntegrationTests extends MySqlIntegrationTest {
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired GroupService groups;
    @Autowired GroupJoinService joins;
    @Autowired GroupMembershipService memberships;
    @Autowired MockMvc mvc;
    @Autowired tools.jackson.databind.json.JsonMapper json;
    @MockitoSpyBean OutboxRepository outbox;
    @MockitoSpyBean com.unidocs.auth.authorization.application.OrganizationSnapshotCache snapshots;
    private record Actor(UUID account,TokenResponse token,String email) { }
    private Actor admin;
    private Actor member;
    private UUID memberAnchor;
    private OrganizationResponse organization;
    private GroupResponse group;
    private Instant now;
    private Actor actor() {
        String email=UUID.randomUUID()+"@example.com";
        RegistrationResponse pending=registrations.register(new RegistrationRequest("Join Actor",email,"test-password-long"));
        String proof=delivery.tokens.get(pending.id());
        registrations.verify(pending.id(),new VerificationRequest(proof));
        RegistrationCompletionResponse identity=provisioning.complete(pending.id(),new RegistrationCompletionRequest(proof));
        return new Actor(identity.accountId(),authentication.login(new LoginRequest(email,"test-password-long")),email);
    }
    @BeforeEach void provision() {
        admin=actor();member=actor();
        organization=organizations.create(admin.token().sessionId(),admin.account(),new OrganizationRequest(admin.account(),UUID.randomUUID(),
                "Join Institution","join-"+UUID.randomUUID(),Organization.Type.UNIVERSITY));
        memberAnchor=UUID.randomUUID();
        jdbc.update("""
            INSERT INTO organization_membership(id,organization_id,account_id,role,status,official_email,version,joined_at,created_at,updated_at)
            VALUES(?,?,?,'MEMBER','ACTIVE',?,1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))
            """,bytes(memberAnchor),bytes(organization.id()),bytes(member.account()),member.email());
        now=Instant.now().truncatedTo(ChronoUnit.MICROS);
    }
    @Test void legacyInstitutionOwnerCannotCreateAnAssignableCourse() {
        assertThatThrownBy(()->groups.create(admin.token().sessionId(),admin.account(),organization.id(),
                new GroupRequest(admin.account(),UUID.randomUUID(),"Course",Group.Type.COURSE,null)))
                .isInstanceOf(GroupFailure.class).extracting("status").isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_course_offering WHERE organization_id=?",Integer.class,bytes(organization.id()))).isZero();
    }
    @Test void legacyRequestApprovalDoesNotReplaceVerifiedStudentSelfJoin() {
        assertThatThrownBy(()->joins.submit(member.token().sessionId(),member.account(),organization.id(),UUID.randomUUID(),
                new GroupJoinRequests.Submit(member.account(),UUID.randomUUID(),"STUDENT","Retired request path")))
                .isInstanceOf(GroupFailure.class).extracting("status").isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_student_course WHERE organization_id=?",Integer.class,bytes(organization.id()))).isZero();
    }
    @Test void legacyOrganizationOwnerCannotApproveAStudentThroughARequestIdentifier() {
        assertThatThrownBy(()->joins.review(admin.token().sessionId(),admin.account(),organization.id(),UUID.randomUUID(),UUID.randomUUID(),
                new GroupJoinRequests.Review(admin.account(),true,"STUDENT",now,null,"Retired approval")))
                .isInstanceOf(GroupFailure.class).extracting("status").isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM group_membership WHERE organization_id=?",Integer.class,bytes(organization.id()))).isZero();
    }
}