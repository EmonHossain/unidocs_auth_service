package com.unidocs.auth.registration;

import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authentication.api.LoginRequest;
import com.unidocs.auth.authentication.api.TokenResponse;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.authentication.application.AuthenticationService;
import com.unidocs.auth.authorization.api.InternalAuthorizationRequest;
import com.unidocs.auth.authorization.api.InternalAuthorizationResponse;
import com.unidocs.auth.authorization.api.InternalAccountAuthorizationRequest;
import com.unidocs.auth.authorization.api.InternalAccountAuthorizationResponse;
import com.unidocs.auth.authorization.api.InternalGroupAuthorizationRequest;
import com.unidocs.auth.authorization.api.InternalGroupAuthorizationResponse;
import com.unidocs.auth.authorization.application.InternalAuthorizationService;
import com.unidocs.auth.authorization.application.OrganizationSnapshotCache;
import com.unidocs.auth.organization.api.OrganizationRequest;
import com.unidocs.auth.organization.api.OrganizationResponse;
import com.unidocs.auth.organization.application.OrganizationFailure;
import com.unidocs.auth.organization.application.OrganizationService;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.group.api.GroupRequest;
import com.unidocs.auth.group.api.GroupResponse;
import com.unidocs.auth.group.api.GroupAssignmentRequest;
import com.unidocs.auth.group.api.GroupMembershipResponse;
import com.unidocs.auth.group.application.GroupService;
import com.unidocs.auth.group.application.GroupMembershipService;
import com.unidocs.auth.group.domain.Group;
import com.unidocs.auth.registration.api.RegistrationCompletionRequest;
import com.unidocs.auth.registration.api.RegistrationCompletionResponse;
import com.unidocs.auth.registration.api.RegistrationRequest;
import com.unidocs.auth.registration.api.RegistrationResponse;
import com.unidocs.auth.registration.api.VerificationRequest;
import com.unidocs.auth.registration.application.RegistrationProvisioningService;
import com.unidocs.auth.registration.application.RegistrationService;
import com.unidocs.auth.security.jwt.AccessTokens;
import com.unidocs.auth.security.jwt.JwtKeyRing;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doThrow;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "auth.internal-authorization.enabled=true",
        "auth.internal-authorization.issuer=https://identity.example",
        "auth.internal-authorization.audience=iam-internal",
        "auth.internal-authorization.jwk-set-uri=https://identity.example/jwks",
        "auth.internal-authorization.service-subjects=document-service"
})
@AutoConfigureMockMvc
@Import(RegistrationIntegrationTests.DeliveryConfiguration.class)
class InternalAuthorizationIntegrationTests extends MySqlIntegrationTest {
    @Autowired InternalAuthorizationService authorization;
    @Autowired RegistrationService registrations;
    @Autowired RegistrationProvisioningService provisioning;
    @Autowired RegistrationIntegrationTests.CapturingDelivery delivery;
    @Autowired AuthenticationService authentication;
    @Autowired OrganizationService organizations;
    @Autowired AccessTokens accessTokens;
    @Autowired JwtKeyRing keys;
    @Autowired CacheManager caches;
    @Autowired MockMvc mvc;
    @Autowired GroupService groups;
    @Autowired GroupMembershipService memberships;
    @MockitoSpyBean OrganizationRepository organizationRepository;
    @Value("${auth.jwt.issuer}") String issuer;
    @Value("${auth.jwt.audience}") String audience;
    private RegistrationCompletionResponse identity;
    private TokenResponse token;
    private OrganizationResponse organization;

    @BeforeEach
    void provision() {
        String email = UUID.randomUUID() + "@example.com";
        RegistrationResponse pending = registrations.register(new RegistrationRequest("Authorization User", email, "test-password-long"));
        String proof = delivery.tokens.get(pending.id());
        registrations.verify(pending.id(), new VerificationRequest(proof));
        identity = provisioning.complete(pending.id(), new RegistrationCompletionRequest(proof));
        token = authentication.login(new LoginRequest(email, "test-password-long"));
        organization = organizations.create(token.sessionId(), identity.accountId(), new OrganizationRequest(
                identity.accountId(), UUID.randomUUID(), "Authorization Institution", "authorization-" + UUID.randomUUID(), Organization.Type.UNIVERSITY));
        caches.getCache("organization-entitlements").clear();
    }

    private InternalAuthorizationRequest request() {
        return new InternalAuthorizationRequest(identity.accountId(), organization.id());
    }

    private InternalAuthorizationResponse authorize() {
        return authorization.authorize("Bearer " + token.accessToken(), request());
    }

    @Test
    void currentGrantAndMembershipReturnFreshNoncacheableEntitlement() {
        Instant before = Instant.now();
        InternalAuthorizationResponse result = authorize();
        assertThat(result.accountId()).isEqualTo(identity.accountId());
        assertThat(result.organizationId()).isEqualTo(organization.id());
        assertThat(result.membershipId()).isEqualTo(organization.membershipId());
        assertThat(result.role()).isEqualTo(OrganizationMembership.Role.OWNER);
        assertThat(result.membershipVersion()).isEqualTo(1);
        assertThat(result.authorizationVersion()).isEqualTo(1);
        assertThat(result.checkedAt()).isBetween(before, Instant.now());
        assertThat(result.expiresAt()).isEqualTo(result.checkedAt());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"Basic credentials", "Bearer ", "Bearer attacker.invalid.token", "Bearer token token"})
    void invalidDelegatedAuthenticationFailsClosed(String header) {
        assertThatThrownBy(() -> authorization.authorize(header, request())).isInstanceOf(AuthenticationFailure.class);
    }

    @Test
    void forgedSignatureAndExpiredSignedTokenFailClosed() {
        String valid = token.accessToken();
        int signature = valid.lastIndexOf('.') + 1;
        String forged = valid.substring(0, signature) + (valid.charAt(signature) == 'A' ? 'B' : 'A') + valid.substring(signature + 1);
        assertThatThrownBy(() -> authorization.authorize("Bearer " + forged, request())).isInstanceOf(AuthenticationFailure.class);
        AccessTokens expiredTokens = new AccessTokens(keys, Clock.fixed(Instant.now().minusSeconds(600), ZoneOffset.UTC), issuer, audience);
        String expired = expiredTokens.issue(identity.accountId(), token.sessionId());
        assertThatThrownBy(() -> authorization.authorize("Bearer " + expired, request())).isInstanceOf(AuthenticationFailure.class);
    }

    @Test
    void signedSubjectAndSessionMustMatchAuthoritativeSessionIdentity() {
        String differentSubject = accessTokens.issue(UUID.randomUUID(), token.sessionId());
        String missingSession = accessTokens.issue(identity.accountId(), UUID.randomUUID());
        assertThatThrownBy(() -> authorization.authorize("Bearer " + differentSubject, request())).isInstanceOf(AuthenticationFailure.class);
        assertThatThrownBy(() -> authorization.authorize("Bearer " + missingSession, request())).isInstanceOf(AuthenticationFailure.class);
    }

    @Test
    void requestedAccountAndOrganizationCannotSupplyAuthority() {
        assertThatThrownBy(() -> authorization.authorize("Bearer " + token.accessToken(),
                new InternalAuthorizationRequest(UUID.randomUUID(), organization.id())))
                .isInstanceOf(OrganizationFailure.class).extracting("status").isEqualTo(HttpStatus.FORBIDDEN);
        assertThatThrownBy(() -> authorization.authorize("Bearer " + token.accessToken(),
                new InternalAuthorizationRequest(identity.accountId(), UUID.randomUUID())))
                .isInstanceOf(OrganizationFailure.class).extracting("status").isEqualTo(HttpStatus.FORBIDDEN);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "UPDATE user_session SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6)",
            "UPDATE user_account SET status='DISABLED'",
            "UPDATE login_identity SET credential_version=credential_version+1",
            "UPDATE session_account_grant SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6),revocation_reason='LOGOUT'",
            "UPDATE session_account_grant SET authenticated_at=UTC_TIMESTAMP(6)-INTERVAL 2 HOUR,last_activity_at=UTC_TIMESTAMP(6)-INTERVAL 2 HOUR,idle_expires_at=UTC_TIMESTAMP(6)-INTERVAL 1 HOUR,absolute_expires_at=UTC_TIMESTAMP(6)-INTERVAL 1 SECOND"
    })
    void revokedOrExpiredSessionStateOverridesValidJwt(String mutation) {
        authorize();
        jdbc.update(mutation);
        assertThatThrownBy(this::authorize).isInstanceOf(AuthenticationFailure.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "UPDATE organization_membership SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6),revoked_by=id",
            "UPDATE organization SET status='DISABLED'",
            "UPDATE organization_auth_policy SET enabled=false",
            "UPDATE organization_auth_policy SET require_mfa=true"
    })
    void staleSnapshotCannotOverrideCurrentMembershipOrPolicy(String mutation) {
        authorize();
        caches.getCache("organization-entitlements").put(new OrganizationSnapshotCache.Key(identity.accountId(), organization.id()), organization);
        jdbc.update(mutation);
        assertThat(caches.getCache("organization-entitlements").get(new OrganizationSnapshotCache.Key(identity.accountId(), organization.id()), OrganizationResponse.class))
                .isEqualTo(organization);
        assertThatThrownBy(this::authorize).isInstanceOf(OrganizationFailure.class).extracting("status").isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void subsequentCheckReturnsCurrentVersionsAndRoleDespiteStaleSnapshot() {
        caches.getCache("organization-entitlements").put(new OrganizationSnapshotCache.Key(identity.accountId(), organization.id()), organization);
        jdbc.update("UPDATE organization SET authorization_version=authorization_version+1");
        jdbc.update("UPDATE organization_membership SET version=version+1,role='ADMIN'");
        InternalAuthorizationResponse result = authorize();
        assertThat(result.role()).isEqualTo(OrganizationMembership.Role.ADMIN);
        assertThat(result.membershipVersion()).isEqualTo(2);
        assertThat(result.authorizationVersion()).isEqualTo(2);
    }

    @Test
    void serviceScopedControllerReturnsEntitlementAndNoStore() throws Exception {
        mvc.perform(post("/api/v1/internal/authorization/organization")
                .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_iam.authorization.read")))
                .header("X-Delegated-Authorization", "Bearer " + token.accessToken())
                .contentType("application/json").content("{\"accountId\":\"" + identity.accountId()
                        + "\",\"organizationId\":\"" + organization.id() + "\"}"))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.accountId").value(identity.accountId().toString()))
                .andExpect(jsonPath("$.membershipId").value(organization.membershipId().toString()));
    }

    @Test
    void controllerRejectsMissingIdsAndDelegatedAuthentication() throws Exception {
        mvc.perform(post("/api/v1/internal/authorization/organization")
                .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_iam.authorization.read")))
                .header("X-Delegated-Authorization", "Bearer " + token.accessToken())
                .contentType("application/json").content("{}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/internal/authorization/organization")
                .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_iam.authorization.read")))
                .contentType("application/json").content("{\"accountId\":\"" + identity.accountId()
                        + "\",\"organizationId\":\"" + organization.id() + "\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void authoritativeDatabaseOutageCannotReturnPreviousEntitlement() {
        authorize();
        caches.getCache("organization-entitlements").put(new OrganizationSnapshotCache.Key(identity.accountId(), organization.id()), organization);
        doThrow(new DataAccessResourceFailureException("test-only"))
                .when(organizationRepository).visibility(identity.accountId(), "LOGIN", organization.id());
        try {
            assertThatThrownBy(this::authorize).isInstanceOf(DataAccessResourceFailureException.class);
        } finally {
            doCallRealMethod().when(organizationRepository).visibility(identity.accountId(), "LOGIN", organization.id());
        }
        assertThat(authorize().membershipId()).isEqualTo(organization.membershipId());
    }

    @Test
    void personalAccountEvidenceRequiresCurrentSelectedGrant() throws Exception {
        InternalAccountAuthorizationResponse result = authorization.authorizeAccount("Bearer " + token.accessToken(),
                new InternalAccountAuthorizationRequest(identity.accountId()));
        assertThat(result.accountId()).isEqualTo(identity.accountId());
        assertThat(result.sessionId()).isEqualTo(token.sessionId());
        assertThat(result.authMethod()).isEqualTo("LOGIN");
        assertThat(result.credentialVersion()).isEqualTo(1);
        assertThat(result.accountType()).isEqualTo("PERSONAL");
        assertThat(result.expiresAt()).isEqualTo(result.checkedAt());
        mvc.perform(post("/api/v1/internal/authorization/account")
                .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_iam.authorization.read")))
                .header("X-Delegated-Authorization", "Bearer " + token.accessToken())
                .contentType("application/json").content("{\"accountId\":\"" + identity.accountId() + "\"}"))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.sessionId").value(token.sessionId().toString()));
        assertThatThrownBy(() -> authorization.authorizeAccount("Bearer " + token.accessToken(),
                new InternalAccountAuthorizationRequest(UUID.randomUUID())))
                .isInstanceOf(OrganizationFailure.class).extracting("status").isEqualTo(HttpStatus.FORBIDDEN);
        jdbc.update("UPDATE session_account_grant SET status='REVOKED',revoked_at=UTC_TIMESTAMP(6),revocation_reason='LOGOUT'");
        assertThatThrownBy(() -> authorization.authorizeAccount("Bearer " + token.accessToken(),
                new InternalAccountAuthorizationRequest(identity.accountId()))).isInstanceOf(AuthenticationFailure.class);
    }

    private GroupResponse createGroup() {
        return groups.create(token.sessionId(), identity.accountId(), organization.id(),
                new GroupRequest(identity.accountId(), UUID.randomUUID(), "Documents Team", Group.Type.TEAM, null));
    }

    private GroupMembershipResponse assignGroup(GroupResponse group) {
        return memberships.assign(token.sessionId(), identity.accountId(), organization.id(), group.id(),
                new GroupAssignmentRequest(identity.accountId(), UUID.randomUUID(), identity.accountId(), "maintainer",
                        Instant.now().minusSeconds(1).truncatedTo(ChronoUnit.MICROS), null));
    }

    private InternalGroupAuthorizationResponse authorizeGroup(GroupResponse group) {
        return authorization.authorizeGroup("Bearer " + token.accessToken(),
                new InternalGroupAuthorizationRequest(identity.accountId(), organization.id(), group.id()));
    }

    @Test
    void legacyOrganizationOwnershipCannotSupplyStudentCourseAuthority() {
        assertThatThrownBy(this::createGroup).isInstanceOf(com.unidocs.auth.group.application.GroupFailure.class);
        UUID group=legacyCourse();
        assertThatThrownBy(()->authorization.authorizeGroup("Bearer "+token.accessToken(),
                new InternalGroupAuthorizationRequest(identity.accountId(),organization.id(),group)))
                .isInstanceOf(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class);
    }
    @Test
    void aRetainedLegacyAssignmentDoesNotReplaceVerifiedAdmissionAndSelfJoin() {
        UUID group=legacyCourse();
        jdbc.update("""
                INSERT INTO group_membership(id,organization_id,group_id,account_id,organization_membership_id,role,
                    membership_type,source,status,valid_from,version,assigned_by_account_id,assignment_request_id,
                    assignment_fingerprint,created_at,updated_at)
                VALUES(?,?,?,?,?,'OWNER','PERMANENT','ORGANIZATION_ASSIGNMENT','ACTIVE',UTC_TIMESTAMP(6)-INTERVAL 1 DAY,1,?,?,REPEAT('a',64),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))
                """,bytes(UUID.randomUUID()),bytes(organization.id()),bytes(group),bytes(identity.accountId()),bytes(organization.membershipId()),bytes(identity.accountId()),bytes(UUID.randomUUID()));
        assertThatThrownBy(()->authorization.authorizeGroup("Bearer "+token.accessToken(),
                new InternalGroupAuthorizationRequest(identity.accountId(),organization.id(),group)))
                .isInstanceOf(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class);
    }
    private UUID legacyCourse() {
        UUID group=UUID.randomUUID();
        jdbc.update("""
                INSERT INTO iam_group(id,organization_id,name,type,status,version,created_by_account_id,creation_request_id,creation_fingerprint,created_at,updated_at)
                VALUES(?,?,'Legacy course','COURSE','ACTIVE',1,?,?,REPEAT('b',64),UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))
                """,bytes(group),bytes(organization.id()),bytes(identity.accountId()),bytes(UUID.randomUUID()));
        return group;
    }
}
