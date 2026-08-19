package com.unidocs.auth.group.application;

import com.unidocs.auth.authorization.application.ProfessionalAuthorizationService;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import com.unidocs.auth.security.spicedb.SpiceDbPermissionClient;
import com.unidocs.auth.group.persistence.GroupRepository;
import com.unidocs.auth.group.persistence.GroupRuleRepository;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class GroupAuthorityCanaryTests {
    /**
     * Navigation cannot borrow an exact-resource invitation or another operation/scope's graph proof.
     * @param invalid which request binding is absent or mismatched
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings={"missing","scope","operation","tenant","exact"})
    void navigationRejectsMissingOrBorrowedEvidenceBeforeSqlAuthority(String invalid) {
        UUID account=UUID.randomUUID(),organization=UUID.randomUUID(),group=UUID.randomUUID();
        Instant now=Instant.parse("2026-11-01T10:00:00Z");
        SessionRepository sessions=mock(SessionRepository.class);
        GroupRepository groups=mock(GroupRepository.class);
        GroupRuleRepository rules=mock(GroupRuleRepository.class);
        OrganizationRepository organizations=mock(OrganizationRepository.class);
        ProfessionalAuthorizationService professional=mock(ProfessionalAuthorizationService.class);
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        SessionAccountGrant grant=mock(SessionAccountGrant.class);
        when(context.now()).thenReturn(now);
        when(sessions.liveGrant(null,account,now)).thenReturn(Optional.of(grant));
        when(grant.authMethod()).thenReturn("LOGIN");
        when(groups.lockOrganization(organization,false)).thenReturn(true);
        when(organizations.visibility(account,"LOGIN",organization)).thenReturn(Optional.of(
                new OrganizationRepository.Visibility(UUID.randomUUID(),OrganizationMembership.Role.OWNER,1,1)));
        when(professional.professional(organization)).thenReturn(true);
        ProfessionalSpiceDbCanary canary=new ProfessionalSpiceDbCanary(organization.toString(),false,false,false,true,true,
                mock(SessionAccess.class),professional,mock(OperationPolicyCatalogRepository.class),
                mock(SpiceDbPermissionClient.class),mock(JdbcTemplate.class),Clock.systemUTC(),new SimpleMeterRegistry());
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider=mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        ProfessionalSpiceDbCanary.Decision proof=mock(ProfessionalSpiceDbCanary.Decision.class);
        when(proof.organization()).thenReturn(invalid.equals("tenant")?UUID.randomUUID():organization);
        when(proof.group()).thenReturn(invalid.equals("scope")?UUID.randomUUID():group);
        when(proof.operation()).thenReturn(invalid.equals("operation")?"file.read":"workspace.read");
        when(proof.exactResourceAccess()).thenReturn(invalid.equals("exact"));
        GroupAuthority authority=new GroupAuthority(sessions,groups,rules,organizations,professional,provider);

        OperationAuthorizationFailure failure=assertThrows(OperationAuthorizationFailure.class,()->authority.require(
                context,account,organization,group,false,false,false,true,invalid.equals("missing")?null:proof));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE,failure.status());
        verify(professional,never()).require(any(),any(),any(),any(),anyString(),anyString());
    }

    /**
     * Selected navigation retains SQL authority and cannot return access after final graph-fence rejection.
     * @param revoked whether the final transaction rejects the preflight decision
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans={false,true})
    void navigationRevalidatesBeforeReturningAccess(boolean revoked) {
        UUID account=UUID.randomUUID(),organization=UUID.randomUUID(),group=UUID.randomUUID();
        Instant now=Instant.parse("2026-11-01T10:00:00Z");
        SessionRepository sessions=mock(SessionRepository.class);
        GroupRepository groups=mock(GroupRepository.class);
        OrganizationRepository organizations=mock(OrganizationRepository.class);
        ProfessionalAuthorizationService professional=mock(ProfessionalAuthorizationService.class);
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        SessionAccountGrant grant=mock(SessionAccountGrant.class);
        ProfessionalSpiceDbCanary canary=mock(ProfessionalSpiceDbCanary.class);
        ProfessionalSpiceDbCanary.Decision proof=mock(ProfessionalSpiceDbCanary.Decision.class);
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider=mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(context.now()).thenReturn(now);
        when(sessions.liveGrant(null,account,now)).thenReturn(Optional.of(grant));
        when(grant.authMethod()).thenReturn("LOGIN");
        when(groups.lockOrganization(organization,false)).thenReturn(true);
        when(organizations.visibility(account,"LOGIN",organization)).thenReturn(Optional.of(
                new OrganizationRepository.Visibility(UUID.randomUUID(),OrganizationMembership.Role.OWNER,1,1)));
        when(professional.professional(organization)).thenReturn(true);
        GroupAuthority authority=new GroupAuthority(sessions,groups,mock(GroupRuleRepository.class),organizations,professional,provider);
        if(revoked) when(canary.revalidate(proof,context,account,organization)).thenThrow(
                new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE,"SPICEDB_AUTHORIZATION_UNAVAILABLE"));

        if(revoked) assertThrows(OperationAuthorizationFailure.class,()->authority.require(
                context,account,organization,group,false,false,false,true,proof));
        else assertEquals(grant,authority.require(context,account,organization,group,false,false,false,true,proof).grant());
        org.mockito.InOrder order=inOrder(canary,professional);
        order.verify(canary).requireContentDecision(organization,group,"workspace.read",false,proof);
        order.verify(professional).require(context,account,organization,group,"document-service","workspace.read");
        order.verify(canary).revalidate(proof,context,account,organization);
    }

    @Test
    void managerCannotUseLegacyAuthorityWhenGraphDecisionIsMissing() {
        UUID account=UUID.randomUUID(),organization=UUID.randomUUID(),group=UUID.randomUUID();
        Instant now=Instant.parse("2026-10-19T12:00:00Z");
        SessionRepository sessions=mock(SessionRepository.class);
        GroupRepository groups=mock(GroupRepository.class);
        GroupRuleRepository rules=mock(GroupRuleRepository.class);
        OrganizationRepository organizations=mock(OrganizationRepository.class);
        ProfessionalAuthorizationService professional=mock(ProfessionalAuthorizationService.class);
        SessionAccess.Context context=mock(SessionAccess.Context.class);
        SessionAccountGrant grant=mock(SessionAccountGrant.class);
        ProfessionalSpiceDbCanary canary=new ProfessionalSpiceDbCanary(organization.toString(),false,true,true,
                mock(SessionAccess.class),professional,mock(OperationPolicyCatalogRepository.class),
                mock(SpiceDbPermissionClient.class),mock(JdbcTemplate.class),Clock.systemUTC(),new SimpleMeterRegistry());
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider=mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        when(context.now()).thenReturn(now);
        when(sessions.liveGrant(null,account,now)).thenReturn(Optional.of(grant));
        when(grant.authMethod()).thenReturn("LOGIN");
        when(groups.lockOrganization(organization,true)).thenReturn(true);
        when(organizations.visibility(account,"LOGIN",organization)).thenReturn(Optional.of(
                new OrganizationRepository.Visibility(UUID.randomUUID(),OrganizationMembership.Role.OWNER,1,1)));
        when(professional.professional(organization)).thenReturn(true);
        GroupAuthority authority=new GroupAuthority(sessions,groups,rules,organizations,professional,provider);

        OperationAuthorizationFailure failure=assertThrows(OperationAuthorizationFailure.class,
                ()->authority.require(context,account,organization,group,true,true,false,true,null));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE,failure.status());
        verify(professional,never()).require(any(),any(),any(),any(),anyString(),anyString());
    }

    /** Rejects mismatched scope and final graph revocation at the manager/catalog authority boundary. */
    @Test
    void managerCannotReuseMismatchedOrRevokedGraphDecisions() {
        UUID account = UUID.randomUUID();
        UUID organization = UUID.randomUUID();
        UUID requestedGroup = UUID.randomUUID();
        UUID checkedGroup = UUID.randomUUID();
        Instant now = Instant.parse("2026-10-19T12:00:00Z");
        SessionRepository sessions = mock(SessionRepository.class);
        GroupRepository groups = mock(GroupRepository.class);
        GroupRuleRepository rules = mock(GroupRuleRepository.class);
        OrganizationRepository organizations = mock(OrganizationRepository.class);
        ProfessionalAuthorizationService professional = mock(ProfessionalAuthorizationService.class);
        SessionAccess.Context context = mock(SessionAccess.Context.class);
        SessionAccountGrant grant = mock(SessionAccountGrant.class);
        ProfessionalSpiceDbCanary.Decision decision = mock(ProfessionalSpiceDbCanary.Decision.class);
        when(context.now()).thenReturn(now);
        when(sessions.liveGrant(null, account, now)).thenReturn(Optional.of(grant));
        when(grant.authMethod()).thenReturn("LOGIN");
        when(groups.lockOrganization(organization, true)).thenReturn(true);
        when(organizations.visibility(account, "LOGIN", organization)).thenReturn(Optional.of(
                new OrganizationRepository.Visibility(UUID.randomUUID(), OrganizationMembership.Role.OWNER, 1, 1)));
        when(professional.professional(organization)).thenReturn(true);
        when(decision.enforcing()).thenReturn(true);
        when(decision.operation()).thenReturn("team.access.update");
        when(decision.group()).thenReturn(checkedGroup);
        ProfessionalSpiceDbCanary canary = mock(ProfessionalSpiceDbCanary.class);
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        GroupAuthority authority = new GroupAuthority(sessions, groups, rules, organizations, professional, provider);

        assertThrows(GroupFailure.class, () -> authority.require(context, account, organization, requestedGroup,
                true, true, false, true, decision));
        verify(professional, never()).require(any(), any(), any(), any(), anyString(), anyString());
        when(decision.group()).thenReturn(requestedGroup);
        when(canary.revalidate(decision, context, account, organization)).thenThrow(
                new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE, "SPICEDB_AUTHORIZATION_UNAVAILABLE"));
        assertThrows(OperationAuthorizationFailure.class, () -> authority.require(context, account, organization,
                requestedGroup, true, true, false, true, decision));
        verify(professional, never()).require(any(), any(), any(), any(), anyString(), anyString());
        assertThrows(OperationAuthorizationFailure.class, () -> authority.requireCatalog(context, account,
                organization, requestedGroup, true, decision));
        verify(professional, never()).require(context, account, organization, null, "auth-service", "organization.group.create");
    }
}
