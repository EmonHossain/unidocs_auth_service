package com.unidocs.auth.registration;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authentication.api.LoginRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.group.api.*;
import com.unidocs.auth.group.application.GroupFailure;
import com.unidocs.auth.group.application.GroupMembershipService;
import com.unidocs.auth.group.application.GroupService;
import com.unidocs.auth.group.domain.Group;
import com.unidocs.auth.group.domain.GroupMembership;
import com.unidocs.auth.organization.api.*;
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
class GroupMembershipIntegrationTests extends MySqlIntegrationTest {
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired GroupService groups;
    @Autowired org.springframework.context.ApplicationContext application;
    @Autowired GroupMembershipService memberships;
    @Autowired MockMvc mvc;
    @Autowired tools.jackson.databind.json.JsonMapper json;
    @MockitoSpyBean OutboxRepository outbox;
    @MockitoSpyBean Clock clock;
    @MockitoSpyBean com.unidocs.auth.authorization.application.OrganizationSnapshotCache snapshots;
    private RegistrationCompletionResponse identity;
    private TokenResponse token;
    private OrganizationResponse organization;
    private GroupResponse group;
    private Instant now;

    @BeforeEach void provision() {
        String email = UUID.randomUUID() + "@example.com";
        RegistrationResponse pending = registrations.register(new RegistrationRequest("Membership Admin", email, "test-password-long"));
        String proof = delivery.tokens.get(pending.id());
        registrations.verify(pending.id(), new VerificationRequest(proof));
        identity = provisioning.complete(pending.id(), new RegistrationCompletionRequest(proof));
        token = authentication.login(new LoginRequest(email, "test-password-long"));
        organization = organizations.create(token.sessionId(), identity.accountId(), new OrganizationRequest(identity.accountId(),
                UUID.randomUUID(), "Group Membership Organization", "gm-" + UUID.randomUUID(), Organization.Type.COMPANY));
        token=ProfessionalFixture.administrator(application,token,"test-password-long",organization.id());
        identity=ProfessionalFixture.selected(identity,token.loginAccountId());
        organization=organizations.get(token.sessionId(),identity.accountId(),identity.accountId(),organization.id());
        group = groups.create(token.sessionId(), identity.accountId(), organization.id(),
                new GroupRequest(identity.accountId(), UUID.randomUUID(), "Engineering", Group.Type.TEAM, null));
        now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        doReturn(now).when(clock).instant();
    }
    private GroupAssignmentRequest request(Instant from, Instant until) {
        return new GroupAssignmentRequest(identity.accountId(), UUID.randomUUID(), identity.accountId(), "maintainer", from, until);
    }
    private GroupMembershipResponse assign(GroupAssignmentRequest request) {
        return memberships.assign(token.sessionId(), identity.accountId(), organization.id(), group.id(), request);
    }
    private GroupMembershipService.Page mine() {
        return memberships.mine(token.sessionId(), identity.accountId(), identity.accountId(), organization.id(), null, 50);
    }
    private GroupMembershipResponse revoke(UUID id) {
        return memberships.revoke(token.sessionId(), identity.accountId(), organization.id(), group.id(), id, identity.accountId());
    }
    private int events(String event) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type=?", Integer.class, event);
    }
    private String path() { return "/api/v1/organizations/" + organization.id() + "/groups/" + group.id() + "/memberships"; }

    @Test void assignmentRetryAndRevocationAreTransactionalVersionedAndDoNotGrantAccountAccess() throws Exception {
        GroupAssignmentRequest request = request(now, now.plusSeconds(60));
        GroupMembershipResponse assigned = assign(request);
        assertThat(assign(request)).isEqualTo(assigned);
        assertThat(assigned.effective()).isTrue();
        assertThat(assigned.membershipType()).isEqualTo(GroupMembership.MembershipType.TEMPORARY);
        assertThat(assigned.source()).isEqualTo(GroupMembership.Source.ORGANIZATION_ASSIGNMENT);
        assertThat(assigned.organizationMembershipId()).isEqualTo(organization.membershipId());
        assertThat(mine().memberships()).containsExactly(assigned);
        assertThat(events("GROUP_MEMBER_ASSIGNED")).isEqualTo(1);
        String payload = jdbc.queryForObject("SELECT payload FROM outbox_event WHERE event_type='GROUP_MEMBER_ASSIGNED'", String.class);
        assertThat(json.readTree(payload).get("organizationVersion").asLong()).isEqualTo(2);
        assertThat(json.readTree(payload).get("aggregateVersion").asLong()).isEqualTo(1);
        assertThat(payload).doesNotContain("maintainer", "Engineering", "password");
        GroupMembershipResponse revoked = revoke(assigned.id());
        assertThat(revoked.status()).isEqualTo(GroupMembership.Status.REVOKED);
        assertThat(revoked.version()).isEqualTo(2);
        assertThat(revoked.effective()).isFalse();
        assertThat(revoke(assigned.id())).isEqualTo(revoked);
        assertThat(assign(request).status()).isEqualTo(GroupMembership.Status.REVOKED);
        assertThat(mine().memberships()).isEmpty();
        assertThat(events("GROUP_MEMBER_REVOKED")).isEqualTo(1);
        assertThat(events("ORGANIZATION_GROUP_MEMBERSHIP_CHANGED")).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type IN('GROUP_MEMBER_ASSIGNED','GROUP_MEMBER_REVOKED')", Integer.class)).isEqualTo(2);
        mvc.perform(get(path()).param("accountId", identity.accountId().toString()).header("Authorization", "Bearer " + token.accessToken()))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"));
        assertThat(assign(request(now, null)).id()).isNotEqualTo(assigned.id());
    }
    @Test void validityIsInclusiveAtStartExclusiveAtEndAndDisabledAncestorsHideMemberships() {
        GroupMembershipResponse assigned = assign(request(now.plusSeconds(1), now.plusSeconds(2)));
        assertThat(assigned.effective()).isFalse();
        assertThat(mine().memberships()).isEmpty();
        doReturn(now.plusSeconds(1)).when(clock).instant();
        assertThat(mine().memberships()).hasSize(1);
        doReturn(now.plusSeconds(2)).when(clock).instant();
        assertThat(mine().memberships()).isEmpty();
        doReturn(now.plusSeconds(1)).when(clock).instant();
        GroupResponse child = groups.create(token.sessionId(), identity.accountId(), organization.id(),
                new GroupRequest(identity.accountId(), UUID.randomUUID(), "Child", Group.Type.CLASS, group.id()));
        memberships.assign(token.sessionId(), identity.accountId(), organization.id(), child.id(), request(now, null));
        jdbc.update("UPDATE iam_group SET status='DISABLED' WHERE id=?", bytes(group.id()));
        assertThat(mine().memberships()).isEmpty();
        assertThatThrownBy(() -> assign(request(now, null))).isInstanceOf(GroupFailure.class);
    }
    @Test void ordinaryMembersCanReadOnlyTheirOwnAssignmentsAndCannotSelfClaim() throws Exception {
        assign(request(now, null));
        jdbc.update("UPDATE organization_membership SET role='MEMBER'");
        assertThat(mine().memberships()).hasSize(1);
        assertThatThrownBy(() -> assign(request(now, null))).isInstanceOf(GroupFailure.class);
        assertThatThrownBy(() -> memberships.list(token.sessionId(), identity.accountId(), identity.accountId(), organization.id(), group.id(), null, 50)).isInstanceOf(GroupFailure.class);
        mvc.perform(post(path()).header("Authorization", "Bearer " + token.accessToken()).contentType("application/json")
                .content("{\"accountId\":\"" + identity.accountId() + "\",\"requestId\":\"" + UUID.randomUUID() + "\",\"memberAccountId\":\"" + identity.accountId()
                        + "\",\"role\":\"OWNER\",\"validFrom\":\"" + now + "\"}"))
                .andExpect(status().isForbidden());
    }
    @ParameterizedTest
    @ValueSource(strings={"UPDATE organization SET status='DISABLED'", "UPDATE organization_auth_policy SET enabled=false",
            "UPDATE organization_auth_policy SET require_mfa=true", "UPDATE organization_membership SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6),revoked_by=id"})
    void currentOrganizationAuthorityKillsDescendantAccess(String mutation) {
        GroupMembershipResponse assigned = assign(request(now, null));
        jdbc.update(mutation);
        assertThatThrownBy(this::mine).isInstanceOf(GroupFailure.class);
        assertThatThrownBy(() -> assign(request(now, null))).isInstanceOf(GroupFailure.class);
        assertThatThrownBy(() -> revoke(assigned.id())).isInstanceOf(GroupFailure.class);
    }
    @Test void targetMustHaveCurrentMembershipInSameOrganizationAndAnchorIsEnforcedInDatabase() {
        OrganizationResponse other = organizations.create(token.sessionId(), identity.accountId(), new OrganizationRequest(identity.accountId(), UUID.randomUUID(),
                "Other", "gm-other-" + UUID.randomUUID(), Organization.Type.COMPANY));
        GroupMembershipResponse assigned = assign(request(now, null));
        assertThatThrownBy(() -> memberships.assign(token.sessionId(), identity.accountId(), other.id(), group.id(), request(now, null))).isInstanceOf(GroupFailure.class);
        assertThatThrownBy(() -> assign(new GroupAssignmentRequest(identity.accountId(), UUID.randomUUID(), UUID.randomUUID(), "member", now, null))).isInstanceOf(GroupFailure.class);
        assertThatThrownBy(() -> jdbc.update("UPDATE group_membership SET organization_membership_id=? WHERE id=?", bytes(other.membershipId()), bytes(assigned.id())))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
    @Test void retiredOrganizationMembershipDoesNotSupplyAssignmentsToFreshMembership() {
        assign(request(now, null));
        jdbc.update("UPDATE organization_membership SET status='PURGED',revoked_at=UTC_TIMESTAMP(6),revoked_by=id WHERE id=?", bytes(organization.membershipId()));
        UUID fresh = UUID.randomUUID();
        jdbc.update("""
            INSERT INTO organization_membership(id,organization_id,account_id,role,status,official_email,version,joined_at,created_at,updated_at)
            VALUES(?,?,?,'OWNER','ACTIVE','member@example.com',1,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))
            """, bytes(fresh), bytes(organization.id()), bytes(identity.accountId()));
        assertThat(mine().memberships()).isEmpty();
        assertThatThrownBy(()->assign(request(now,null))).isInstanceOf(GroupFailure.class);
    }
    @Test void conflictingRetriesDuplicatesAndInvalidWindowsDoNotMutateState() {
        GroupAssignmentRequest request = request(now, null);
        assign(request);
        assertThatThrownBy(() -> assign(request(now, null))).isInstanceOf(GroupFailure.class).extracting("status").isEqualTo(HttpStatus.CONFLICT);
        assertThatThrownBy(() -> assign(new GroupAssignmentRequest(identity.accountId(), request.requestId(), identity.accountId(), "changed", now, null)))
                .isInstanceOf(GroupFailure.class).extracting("status").isEqualTo(HttpStatus.CONFLICT);
        for (GroupAssignmentRequest invalid : List.of(request(now, now), request(now, now.minusSeconds(1)), request(now.minusSeconds(2), now.minusSeconds(1)), request(now.plusNanos(1), null))) {
            assertThatThrownBy(() -> assign(invalid)).isInstanceOf(GroupFailure.class).extracting("status").isEqualTo(HttpStatus.BAD_REQUEST);
        }
        assertThat(events("GROUP_MEMBER_ASSIGNED")).isEqualTo(1);
    }
    @Test void outboxFailureRollsBackAssignmentAuditAndAuthorizationVersion() {
        doThrow(new TransientDataAccessResourceException("Synthetic failure")).when(outbox).groupMembershipChanged(any(), anyLong(), anyString(), any());
        assertThatThrownBy(() -> assign(request(now, null))).isInstanceOf(TransientDataAccessResourceException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM group_membership", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?", Long.class, bytes(organization.id()))).isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM security_audit_event WHERE event_type='GROUP_MEMBER_ASSIGNED'", Integer.class)).isZero();
    }
    @Test void concurrentRetryCommitsOneAssignmentAndOneVersion() throws Exception {
        GroupAssignmentRequest request = request(now, null);
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
            Future<GroupMembershipResponse> first = executor.submit(() -> { start.await(); return assign(request); });
            Future<GroupMembershipResponse> second = executor.submit(() -> { start.await(); return assign(request); });
            start.countDown();
            assertThat(first.get(15, TimeUnit.SECONDS)).isEqualTo(second.get(15, TimeUnit.SECONDS));
        }
        assertThat(events("GROUP_MEMBER_ASSIGNED")).isEqualTo(1);
    }
    @Test void apiRejectsMissingAuthenticationInvalidInputAndUnboundedPages() throws Exception {
        mvc.perform(get(path()).param("accountId", identity.accountId().toString()).header("X-User-Id", identity.accountId().toString())).andExpect(status().isUnauthorized());
        mvc.perform(post(path()).header("Authorization", "Bearer " + token.accessToken()).contentType("application/json").content("{}"))
                .andExpect(status().isBadRequest());
        assertThatThrownBy(() -> memberships.list(token.sessionId(), identity.accountId(), identity.accountId(), organization.id(), group.id(), null, 101))
                .isInstanceOf(GroupFailure.class).extracting("status").isEqualTo(HttpStatus.BAD_REQUEST);
        String payload="{\"accountId\":\""+identity.accountId()+"\",\"requestId\":\""+UUID.randomUUID()+"\",\"memberAccountId\":\""+identity.accountId()
                +"\",\"role\":\"member\",\"validFrom\":\""+now+"\"}";
        mvc.perform(post(path()).header("Authorization","Bearer "+token.accessToken()).contentType("application/json").content(payload))
                .andExpect(status().isCreated()).andExpect(header().string("Cache-Control","no-store")).andExpect(jsonPath("$.effective").value(true));
        mvc.perform(get("/api/v1/organizations/"+organization.id()+"/me/group-memberships").param("accountId",identity.accountId().toString())
                .header("Authorization","Bearer "+token.accessToken())).andExpect(status().isOk()).andExpect(jsonPath("$.memberships.length()").value(1));
        UUID membership=mine().memberships().getFirst().id();
        mvc.perform(post(path()+"/"+membership+"/revoke").header("Authorization","Bearer "+token.accessToken()).contentType("application/json")
                .content("{\"accountId\":\""+identity.accountId()+"\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("REVOKED"));
    }
    @Test void catalogPaginationIncludesRevokedHistoryAndUsesStableUniqueCursors() {
        GroupMembershipResponse first = assign(request(now,null));
        revoke(first.id());
        GroupMembershipResponse second = assign(request(now,null));
        GroupMembershipService.Page page = memberships.list(token.sessionId(),identity.accountId(),identity.accountId(),organization.id(),group.id(),null,1);
        GroupMembershipService.Page next = memberships.list(token.sessionId(),identity.accountId(),identity.accountId(),organization.id(),group.id(),page.nextCursor(),1);
        assertThat(page.memberships()).hasSize(1);
        assertThat(next.memberships()).hasSize(1);
        assertThat(List.of(page.memberships().getFirst().id(),next.memberships().getFirst().id())).containsExactlyInAnyOrder(first.id(),second.id());
        assertThat(next.nextCursor()).isNull();
        assertThat(mine().memberships()).containsExactly(second);
    }
    @Test void cacheInvalidationRunsAfterCommitAndFailureCannotUndoDurableAssignment() {
        doAnswer(invocation -> {
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM group_membership",Integer.class)).isEqualTo(1);
            throw new IllegalStateException("Synthetic cache outage");
        }).when(snapshots).invalidate(eq(organization.id()),eq(2L));
        GroupMembershipResponse assigned=assign(request(now,null));
        assertThat(assigned.effective()).isTrue();
        assertThat(mine().memberships()).containsExactly(assigned);
        assertThat(events("GROUP_MEMBER_ASSIGNED")).isEqualTo(1);
        verify(snapshots).invalidate(organization.id(),2L);
    }
}
