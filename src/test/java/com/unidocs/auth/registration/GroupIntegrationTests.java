package com.unidocs.auth.registration;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
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
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authentication.api.LoginRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.group.api.GroupRequest;
import com.unidocs.auth.group.api.GroupResponse;
import com.unidocs.auth.group.application.GroupFailure;
import com.unidocs.auth.group.application.GroupService;
import com.unidocs.auth.group.domain.Group;
import com.unidocs.auth.organization.api.OrganizationRequest;
import com.unidocs.auth.organization.api.OrganizationResponse;
import com.unidocs.auth.organization.application.OrganizationService;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import com.unidocs.auth.registration.api.*;
import com.unidocs.auth.registration.application.RegistrationProvisioningService;
import com.unidocs.auth.registration.application.RegistrationService;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
class GroupIntegrationTests extends MySqlIntegrationTest {
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired GroupService groups;
    @Autowired org.springframework.context.ApplicationContext application;
    @Autowired MockMvc mvc;
    @Autowired tools.jackson.databind.json.JsonMapper json;
    @MockitoSpyBean OutboxRepository outbox;
    private RegistrationCompletionResponse identity;
    private TokenResponse token;
    private OrganizationResponse organization;

    @BeforeEach void provision() {
        org.springframework.security.core.context.SecurityContextHolder.clearContext();
        String email = UUID.randomUUID() + "@example.com";
        RegistrationResponse pending = registrations.register(new RegistrationRequest("Group Admin", email, "test-password-long"));
        String proof = delivery.tokens.get(pending.id());
        registrations.verify(pending.id(), new VerificationRequest(proof));
        identity = provisioning.complete(pending.id(), new RegistrationCompletionRequest(proof));
        token = authentication.login(new LoginRequest(email, "test-password-long"));
        organization = organizations.create(token.sessionId(), identity.accountId(), new OrganizationRequest(identity.accountId(),
                UUID.randomUUID(), "Group Organization", "group-" + UUID.randomUUID(), Organization.Type.COMPANY));
        token=ProfessionalFixture.administrator(application,token,"test-password-long",organization.id());
        identity=ProfessionalFixture.selected(identity,token.loginAccountId());
        organization=organizations.get(token.sessionId(),identity.accountId(),identity.accountId(),organization.id());
        clearInvocations(outbox);
    }
    private GroupRequest request(String name, UUID parent) {
        return new GroupRequest(identity.accountId(), UUID.randomUUID(), name, Group.Type.TEAM, parent);
    }
    private GroupResponse create(GroupRequest request) { return groups.create(token.sessionId(), identity.accountId(), organization.id(), request); }
    private GroupResponse read(UUID id) { return groups.get(token.sessionId(), identity.accountId(), identity.accountId(), organization.id(), id); }
    private int count(String table) { return jdbc.queryForObject("SELECT COUNT(*) FROM " + table, Integer.class); }
    private String path() { return "/api/v1/organizations/" + organization.id() + "/groups"; }

    @Test void creationIsIdempotentAuditedAndTransactionalWithoutNewGrants() throws Exception {
        GroupRequest request = request(" Engineering ", null);
        int memberships = count("organization_membership");
        int grants = count("session_account_grant");
        GroupResponse group = create(request);
        assertThat(create(request)).isEqualTo(group);
        assertThat(group.name()).isEqualTo("Engineering");
        assertThat(group.version()).isEqualTo(1);
        assertThat(count("iam_group")).isEqualTo(1);
        assertThat(count("organization_membership")).isEqualTo(memberships);
        assertThat(count("session_account_grant")).isEqualTo(grants);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='GROUP_CREATED'", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type='GROUP_CREATED'", Integer.class)).isEqualTo(1);
        String payload = jdbc.queryForObject("SELECT payload FROM outbox_event WHERE event_type='GROUP_CREATED'", String.class);
        assertThat(json.readTree(payload).get("aggregateVersion").asLong()).isEqualTo(1);
        assertThat(json.readTree(payload).get("aggregateId").asText()).isEqualTo(group.id().toString());
        assertThat(payload).doesNotContain("Engineering", "password");
        mvc.perform(get(path() + "/" + group.id()).param("accountId", identity.accountId().toString())
                .header("Authorization", "Bearer " + token.accessToken())).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store")).andExpect(jsonPath("$.name").value("Engineering"));
        assertThatThrownBy(() -> create(new GroupRequest(identity.accountId(), request.requestId(), "Changed", Group.Type.TEAM, null)))
                .isInstanceOf(GroupFailure.class).extracting("status").isEqualTo(org.springframework.http.HttpStatus.CONFLICT);
    }
    @Test void hierarchyIsOrganizationScopedAndDisabledAncestorsHideDescendants() {
        GroupResponse parent = create(request("Parent", null));
        GroupResponse child = create(request("Child", parent.id()));
        assertThat(read(child.id()).parentGroupId()).isEqualTo(parent.id());
        OrganizationResponse other = organizations.create(token.sessionId(), identity.accountId(), new OrganizationRequest(identity.accountId(),
                UUID.randomUUID(), "Other", "other-" + UUID.randomUUID(), Organization.Type.COMPANY));
        assertThatThrownBy(() -> groups.create(token.sessionId(), identity.accountId(), other.id(), request("Bad parent", parent.id())))
                .isInstanceOf(GroupFailure.class);
        assertThatThrownBy(() -> create(request("Missing parent", UUID.randomUUID()))).isInstanceOf(GroupFailure.class);
        assertThatThrownBy(() -> jdbc.update("UPDATE iam_group SET organization_id=? WHERE id=?", bytes(other.id()), bytes(child.id())))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> jdbc.update("UPDATE iam_group SET parent_group_id=id WHERE id=?", bytes(parent.id())))
                .rootCause().isInstanceOf(java.sql.SQLException.class).extracting("errorCode").isEqualTo(3819);
        jdbc.update("UPDATE iam_group SET status='DISABLED' WHERE id=?", bytes(parent.id()));
        assertThatThrownBy(() -> read(child.id())).isInstanceOf(GroupFailure.class);
        assertThatThrownBy(() -> create(request("New child", parent.id()))).isInstanceOf(GroupFailure.class);
        assertThat(groups.list(token.sessionId(), identity.accountId(), identity.accountId(), organization.id(), null, 10).groups()).isEmpty();
    }
    @ParameterizedTest
    @ValueSource(strings = {"UPDATE iam_professional_assignment SET status='REVOKED'",
            "UPDATE organization SET status='DISABLED'",
            "UPDATE organization_membership SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6),revoked_by=id",
            "UPDATE organization_auth_policy SET enabled=false", "UPDATE organization_auth_policy SET require_mfa=true",
            "UPDATE organization_auth_policy SET email_domain='example.com'"})
    void currentOrganizationAuthorityIsRequiredForEveryManagementOperation(String mutation) throws Exception {
        GroupRequest request = request("Existing", null);
        GroupResponse group = create(request);
        jdbc.update(mutation);
        Class<? extends Throwable> denial = mutation.startsWith("UPDATE organization_membership SET status")
                || mutation.startsWith("UPDATE organization SET status") || mutation.startsWith("UPDATE organization_auth_policy")
                ? com.unidocs.auth.authentication.application.AuthenticationFailure.class : GroupFailure.class;
        assertThatThrownBy(() -> read(group.id())).isInstanceOf(denial);
        assertThatThrownBy(() -> create(request)).isInstanceOf(denial);
        assertThatThrownBy(() -> groups.list(token.sessionId(), identity.accountId(), identity.accountId(), organization.id(), null, 10))
                .isInstanceOf(denial);
        mvc.perform(get(path() + "/" + group.id()).param("accountId", identity.accountId().toString())
                .header("Authorization", "Bearer " + token.accessToken()))
                .andExpect(status().is(denial == GroupFailure.class ? 403 : 401))
                .andExpect(jsonPath("$.name").doesNotExist());
        assertThat(count("iam_group")).isEqualTo(1);
    }
    @Test void legacyMembershipRoleDoesNotOverrideProfessionalAssignment() {
        GroupResponse group = create(request("Existing", null));
        jdbc.update("UPDATE organization_membership SET role='MEMBER'");
        assertThat(read(group.id())).isEqualTo(group);
        assertThat(create(request("Still authorized", null))).isNotNull();
        assertThat(groups.list(token.sessionId(), identity.accountId(), identity.accountId(), organization.id(), null, 10).groups())
                .hasSize(2);
    }
    @Test void adminCanManageGroupsAndPaginationIsStableAndBounded() {
        jdbc.update("UPDATE organization_membership SET role='ADMIN'");
        GroupResponse first = create(request("First", null));
        GroupResponse second = create(request("Second", null));
        GroupService.Page page = groups.list(token.sessionId(), identity.accountId(), identity.accountId(), organization.id(), null, 1);
        assertThat(page.groups()).hasSize(1);
        GroupService.Page next = groups.list(token.sessionId(), identity.accountId(), identity.accountId(), organization.id(), page.nextCursor(), 1);
        assertThat(next.groups()).hasSize(1);
        assertThat(List.of(page.groups().getFirst().id(), next.groups().getFirst().id())).containsExactlyInAnyOrder(first.id(), second.id());
        assertThat(next.nextCursor()).isNull();
        assertThatThrownBy(() -> groups.list(token.sessionId(), identity.accountId(), identity.accountId(), organization.id(), null, 101))
                .isInstanceOf(GroupFailure.class);
    }
    @Test void outboxFailureRollsBackGroupAndAudit() {
        int audits = count("security_audit_event");
        doThrow(new TransientDataAccessResourceException("Synthetic failure")).when(outbox).groupCreated(any(), any(), any(), any());
        assertThatThrownBy(() -> create(request("Rolled back", null))).isInstanceOf(TransientDataAccessResourceException.class);
        assertThat(count("iam_group")).isZero();
        assertThat(count("security_audit_event")).isEqualTo(audits);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type='GROUP_CREATED'", Integer.class)).isZero();
    }
    @Test void concurrentIdenticalCreationCommitsOnlyOneGroupAndEvent() throws Exception {
        GroupRequest request = request("Concurrent", null);
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
            Future<GroupResponse> first = executor.submit(() -> { start.await(); return create(request); });
            Future<GroupResponse> second = executor.submit(() -> { start.await(); return create(request); });
            start.countDown();
            assertThat(first.get(15, TimeUnit.SECONDS)).isEqualTo(second.get(15, TimeUnit.SECONDS));
        }
        assertThat(count("iam_group")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type='GROUP_CREATED'", Integer.class)).isEqualTo(1);
    }
    @Test void apiValidatesInputsAndCannotTrustClientIdentityHeaders() throws Exception {
        mvc.perform(get(path()).param("accountId", identity.accountId().toString()).header("X-User-Id", identity.accountId().toString()))
                .andExpect(status().isUnauthorized());
        mvc.perform(post(path()).header("Authorization", "Bearer " + token.accessToken()).contentType("application/json")
                .content("{\"name\":\"Group\",\"type\":\"TEAM\"}")).andExpect(status().isBadRequest());
        mvc.perform(post(path()).header("Authorization", "Bearer " + token.accessToken()).contentType("application/json")
                .content("{\"accountId\":\"" + identity.accountId() + "\",\"requestId\":\"" + UUID.randomUUID()
                        + "\",\"name\":\"API Group\",\"type\":\"TEAM\"}"))
                .andExpect(status().isCreated()).andExpect(header().exists("Location"));
        assertThatThrownBy(() -> groups.get(token.sessionId(), identity.accountId(), UUID.randomUUID(), organization.id(), UUID.randomUUID()))
                .isInstanceOf(GroupFailure.class);
    }

    @Test void databaseHierarchyAcceptsDepth32AndRejectsDepth33() {
        GroupResponse parent = create(request("Level 1", null));
        for (int depth = 2; depth <= 32; depth++) {
            parent = create(request("Level " + depth, parent.id()));
        }
        assertThat(read(parent.id()).name()).isEqualTo("Level 32");
        UUID leaf = parent.id();
        assertThatThrownBy(() -> create(request("Too deep", leaf))).isInstanceOf(GroupFailure.class)
                .extracting("status").isEqualTo(org.springframework.http.HttpStatus.BAD_REQUEST);
        assertThat(count("iam_group")).isEqualTo(32);
    }
}
