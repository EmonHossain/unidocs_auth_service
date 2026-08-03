package com.unidocs.auth.authorization.application;

import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.authorization.api.OperationAuthorizationRequest;
import com.unidocs.auth.authorization.api.OperationAuthorizationResponse;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import com.unidocs.auth.group.personal.PersonalGroupAccess;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.student.StudentAuthorization;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** Direct internal-consumer checks: graph evidence cannot be bypassed with a service identity. */
class ProfessionalCollaborationCanaryTests {
    private static final String OPERATION = "organization.collaboration.invite";
    private final UUID account = UUID.randomUUID(), organization = UUID.randomUUID(), group = UUID.randomUUID();
    private final UUID session = UUID.randomUUID();
    private final Instant now = Instant.parse("2026-10-31T12:00:00Z");
    private final Clock clock = mock(Clock.class);
    private final JwtDecoder decoder = mock(JwtDecoder.class);
    private final SessionAccess access = mock(SessionAccess.class);
    private final SessionAccess.Context context = mock(SessionAccess.Context.class);
    private final ProfessionalAuthorizationService professional = mock(ProfessionalAuthorizationService.class);
    private final StudentAuthorization students = mock(StudentAuthorization.class);
    private final ProfessionalSpiceDbCanary canary = mock(ProfessionalSpiceDbCanary.class);
    private final ProfessionalSpiceDbCanary.Decision decision = mock(ProfessionalSpiceDbCanary.Decision.class);
    private final OperationPolicyCandidateCache cache = mock(OperationPolicyCandidateCache.class);
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private OperationAuthorizationService service;
    private JwtAuthenticationToken caller;

    /** Builds independent service and delegated-user identities without creating sessions or fixtures. */
    @BeforeEach
    void configure() {
        when(clock.instant()).thenReturn(now);
        Jwt delegated = jwt(account.toString(), now.plusSeconds(60));
        when(decoder.decode("delegated")).thenReturn(delegated);
        caller = new JwtAuthenticationToken(jwt("document-service", now.plusSeconds(300)),
                List.of(new SimpleGrantedAuthority("SCOPE_iam.authorization.read")));
        SecurityContextHolder.getContext().setAuthentication(caller);
        @SuppressWarnings("unchecked") ObjectProvider<ProfessionalSpiceDbCanary> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(canary);
        service = new OperationAuthorizationService(decoder, access, mock(SessionRepository.class), new OperationRegistry(),
                mock(OperationPolicyCatalogRepository.class), cache, jdbc, clock, new SimpleMeterRegistry(),
                mock(PersonalGroupAccess.class), professional, students, provider);
        when(canary.applies(organization, OPERATION)).thenReturn(true);
        when(canary.check(session, account, account, organization, group, OPERATION)).thenReturn(decision);
        when(decision.enforcing()).thenReturn(true);
        when(access.execute(eq(session), eq(account), any())).thenAnswer(call ->
                call.<Function<SessionAccess.Context, Object>>getArgument(2).apply(context));
    }

    /** Clears the per-thread caller so following tests cannot inherit service authority. */
    @AfterEach
    void clearCaller() {
        SecurityContextHolder.clearContext();
    }

    /** Returns final graph evidence without consulting legacy authority or candidate caches. */
    @Test
    void returnsOnlyFinalGraphEvidenceWithoutLegacyOrCacheAllow() {
        OperationAuthorizationResponse response = mock(OperationAuthorizationResponse.class);
        when(canary.revalidate(decision, context, account, organization)).thenReturn(response);
        assertSame(response, service.evaluate(caller, "Bearer delegated", request()));
        verify(canary).requireDecision(organization, group, OPERATION, decision);
        verifyNoInteractions(professional, cache, jdbc);
    }

    /**
     * Rejects preflight failures before final authorization.
     * @param status graph denial or dependency-failure status
     */
    @ParameterizedTest
    @ValueSource(ints = {403, 503})
    void graphDenialOrOutageCannotFallBack(int status) {
        when(canary.check(session, account, account, organization, group, OPERATION))
                .thenThrow(new OperationAuthorizationFailure(HttpStatus.valueOf(status), "DENIED"));
        assertEquals(status, assertThrows(OperationAuthorizationFailure.class,
                () -> service.evaluate(caller, "Bearer delegated", request())).status().value());
        verifyNoInteractions(access, professional, cache, jdbc);
    }

    /**
     * Rejects final revocation or fence uncertainty without a legacy retry.
     * @param status final authorization failure status
     */
    @ParameterizedTest
    @ValueSource(ints = {403, 503})
    void finalRevocationOrStaleFenceCannotReturnAnAllow(int status) {
        when(canary.revalidate(decision, context, account, organization))
                .thenThrow(new OperationAuthorizationFailure(HttpStatus.valueOf(status), "DENIED"));
        assertEquals(status, assertThrows(OperationAuthorizationFailure.class,
                () -> service.evaluate(caller, "Bearer delegated", request())).status().value());
        verifyNoInteractions(professional, cache, jdbc);
    }

    /** Prevents a delegated token that expires during graph RPCs from entering final authorization. */
    @Test
    void delegatedExpiryDuringGraphCheckCannotEnterFinalAuthorization() {
        when(canary.check(session, account, account, organization, group, OPERATION)).thenAnswer(call -> {
            when(clock.instant()).thenReturn(now.plusSeconds(60));
            return decision;
        });
        assertThrows(AuthenticationFailure.class, () -> service.evaluate(caller, "Bearer delegated", request()));
        verify(canary, never()).revalidate(any(), any(), any(), any());
        verifyNoInteractions(professional, cache, jdbc);
    }

    /** Binds final authorization to the same service caller that initiated graph preflight. */
    @Test
    void callerReplacementDuringGraphCheckCannotBorrowDelegatedAuthority() {
        when(canary.check(session, account, account, organization, group, OPERATION)).thenAnswer(call -> {
            caller = new JwtAuthenticationToken(jwt("document-service", now));
            SecurityContextHolder.getContext().setAuthentication(caller);
            return decision;
        });
        JwtAuthenticationToken original = caller;
        assertEquals(HttpStatus.FORBIDDEN, assertThrows(OperationAuthorizationFailure.class,
                () -> service.evaluate(original, "Bearer delegated", request())).status());
        verify(canary, never()).revalidate(any(), any(), any(), any());
        verifyNoInteractions(professional, cache, jdbc);
    }

    /** Checks service-token expiry independently of the delegated product token's lifetime. */
    @Test
    void serviceExpiryDuringGraphCheckCannotBorrowAStillValidDelegatedIdentity() {
        when(decoder.decode("delegated")).thenReturn(jwt(account.toString(), now.plusSeconds(3600)));
        when(canary.check(session, account, account, organization, group, OPERATION)).thenAnswer(call -> {
            when(clock.instant()).thenReturn(now.plusSeconds(300));
            return decision;
        });
        assertEquals(HttpStatus.FORBIDDEN, assertThrows(OperationAuthorizationFailure.class,
                () -> service.evaluate(caller, "Bearer delegated", request())).status());
        verify(canary, never()).revalidate(any(), any(), any(), any());
        verifyNoInteractions(professional, cache, jdbc);
    }

    /** Rejects a product identity where a trusted Document service caller is required. */
    @Test
    void productIdentityCannotActAsDocumentService() {
        JwtAuthenticationToken product = new JwtAuthenticationToken(jwt(account.toString(), now.plusSeconds(60)));
        SecurityContextHolder.getContext().setAuthentication(product);
        assertThrows(OperationAuthorizationFailure.class, () -> service.evaluate(product, "Bearer delegated", request()));
        verifyNoInteractions(canary, professional, access);
    }

    /** Prevents omission of the group selector from weakening collaboration's scope contract. */
    @Test
    void missingGroupCannotDowngradeToOrganizationPermission() {
        assertThrows(OperationAuthorizationFailure.class, () -> service.evaluate(caller, "Bearer delegated",
                new OperationAuthorizationRequest(OPERATION, account, "GROUP", organization, null)));
        verifyNoInteractions(canary, professional, access);
    }

    /**
     * Routes registered content paths through their exact-resource-aware preflight and returns final evidence.
     * @param operation registered content operation
     * @param kind registered resource kind
     * @param exact whether Document presents exact-resource admission
     */
    @ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"workspace.read,WORKSPACE,false", "file.read,FILE,true",
            "folder.read,FOLDER,true", "publication.approve,FILE,false", "file.share.edit,FILE,false"})
    void contentEndpointUsesFinalIntersectionWithoutLegacyFallback(String operation, String kind, boolean exact) {
        when(canary.applies(organization, operation)).thenReturn(true);
        when(canary.checkContent(session, account, account, organization, group, operation, exact)).thenReturn(decision);
        when(decision.enforcing()).thenReturn(false);
        OperationAuthorizationResponse response = mock(OperationAuthorizationResponse.class);
        when(canary.revalidate(decision, context, account, organization)).thenReturn(response);
        assertSame(response, service.evaluate(caller, "Bearer delegated",
                new OperationAuthorizationRequest(operation, account, kind, organization, group, exact)));
        verify(canary).requireContentDecision(organization, group, operation, exact, decision);
        verifyNoInteractions(professional, cache, jdbc);
    }

    /**
     * A graph denial or outage is terminal for content entry paths too.
     * @param status denied or unavailable status
     */
    @ParameterizedTest @ValueSource(ints = {403, 503})
    void contentPreflightFailureCannotFallBack(int status) {
        when(canary.applies(organization, "file.read")).thenReturn(true);
        when(canary.checkContent(session, account, account, organization, group, "file.read", true))
                .thenThrow(new OperationAuthorizationFailure(HttpStatus.valueOf(status), "DENIED"));
        assertEquals(status, assertThrows(OperationAuthorizationFailure.class, () -> service.evaluate(caller,
                "Bearer delegated", new OperationAuthorizationRequest("file.read", account, "FILE", organization, group, true)))
                .status().value());
        verifyNoInteractions(access, professional, cache, jdbc);
    }

    /**
     * A final revocation cannot be replaced with legacy authority after content preflight.
     * @param status denied or unavailable status
     */
    @ParameterizedTest @ValueSource(ints = {403, 503})
    void contentFinalRevocationCannotFallBack(int status) {
        when(canary.applies(organization, "file.read")).thenReturn(true);
        when(canary.checkContent(session, account, account, organization, group, "file.read", true)).thenReturn(decision);
        when(decision.enforcing()).thenReturn(false);
        when(canary.revalidate(decision, context, account, organization))
                .thenThrow(new OperationAuthorizationFailure(HttpStatus.valueOf(status), "DENIED"));
        assertEquals(status, assertThrows(OperationAuthorizationFailure.class, () -> service.evaluate(caller,
                "Bearer delegated", new OperationAuthorizationRequest("file.read", account, "FILE", organization, group, true)))
                .status().value());
        verifyNoInteractions(professional, cache, jdbc);
    }

    /** Expiry during content graph RPCs still prevents final SQL entry. */
    @Test void contentGraphCheckCannotExtendDelegatedExpiry() {
        when(canary.applies(organization, "file.read")).thenReturn(true);
        when(canary.checkContent(session, account, account, organization, group, "file.read", true)).thenAnswer(call -> {
            when(clock.instant()).thenReturn(now.plusSeconds(60)); return decision;
        });
        assertThrows(AuthenticationFailure.class, () -> service.evaluate(caller, "Bearer delegated",
                new OperationAuthorizationRequest("file.read", account, "FILE", organization, group, true)));
        verify(canary, never()).revalidate(any(), any(), any(), any());
        verifyNoInteractions(professional, cache, jdbc);
    }

    /** Invalid exact-resource hints cannot reach preflight or current-authority reads. */
    @Test void unsupportedExactResourceHintCannotSelectAnEasierOperation() {
        assertThrows(OperationAuthorizationFailure.class, () -> service.evaluate(caller, "Bearer delegated",
                new OperationAuthorizationRequest("file.delete.schedule", account, "FILE", organization, group, true)));
        verifyNoInteractions(canary, professional, access);
    }

    /** Direct application-service entry must enforce the verified service scope as well as the service subject. */
    @Test void contentCallerWithoutAuthorizationScopeIsDeniedBeforeGraph() {
        caller = new JwtAuthenticationToken(jwt("document-service", now.plusSeconds(300)));
        caller.setAuthenticated(true);
        assertTrue(caller.isAuthenticated());
        SecurityContextHolder.getContext().setAuthentication(caller);
        assertThrows(OperationAuthorizationFailure.class, () -> service.evaluate(caller, "Bearer delegated",
                new OperationAuthorizationRequest("file.read", account, "FILE", organization, group)));
        verifyNoInteractions(canary, professional, access, jdbc);
    }

    /**
     * Checks the sharing actor before SQL recipient eligibility without manufacturing recipient graph authority.
     * @param mode requested sharing preset
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    @ParameterizedTest @ValueSource(strings = {"VIEW", "EDIT"})
    void sharingActorUsesContentPreflightBeforeRecipientEligibility(String mode) {
        UUID recipient = UUID.randomUUID(), recipientUser = UUID.randomUUID();
        String operation = mode.equals("EDIT") ? "file.share.edit" : "file.share.view";
        when(canary.applies(organization, operation)).thenReturn(true);
        when(canary.checkContent(session, account, account, organization, group, operation, false)).thenReturn(decision);
        when(jdbc.query(anyString(), any(org.springframework.jdbc.core.RowMapper.class), any(byte[].class)))
                .thenReturn(List.of(UUID.randomUUID()));
        when(access.executeForGroups(eq(session), eq(account), anyList(), any())).thenAnswer(call ->
                call.<Function<SessionAccess.Context, Object>>getArgument(3).apply(context));
        when(professional.recipient(organization, group, recipient, mode)).thenReturn(recipientUser);
        service.professionalRecipient(caller, "Bearer delegated",
                new com.unidocs.auth.authorization.api.ProfessionalRecipientRequest(account, organization, group, recipient, mode));
        org.mockito.InOrder order = inOrder(canary, professional);
        order.verify(canary).checkContent(session, account, account, organization, group, operation, false);
        order.verify(canary).requireContentDecision(organization, group, operation, false, decision);
        order.verify(canary).revalidate(decision, context, account, organization);
        order.verify(professional).recipient(organization, group, recipient, mode);
        verify(professional, never()).require(any(), any(), any(), any(), any(), any());
        verifyNoInteractions(cache);
    }

    /**
     * Sharing graph failures stop before recipient SQL and cannot grant access through a fallback.
     * @param status denied or unavailable status
     */
    @ParameterizedTest @ValueSource(ints = {403, 503})
    void sharingActorGraphFailureStopsBeforeRecipientLookup(int status) {
        when(canary.applies(organization, "file.share.edit")).thenReturn(true);
        when(canary.checkContent(session, account, account, organization, group, "file.share.edit", false))
                .thenThrow(new OperationAuthorizationFailure(HttpStatus.valueOf(status), "DENIED"));
        assertEquals(status, assertThrows(OperationAuthorizationFailure.class,
                () -> service.professionalRecipient(caller, "Bearer delegated",
                        new com.unidocs.auth.authorization.api.ProfessionalRecipientRequest(account, organization, group,
                                UUID.randomUUID(), "EDIT"))).status().value());
        verify(access).execute(eq(session),eq(account),any());
        verifyNoInteractions(professional, jdbc, cache);
    }

    /** Tenant classification runs under actual Spring transaction state; graph calls remain outside it. */
    @Test void sharingClassificationUsesShortTransactionsAroundExternalGraphCheck() {
        org.springframework.transaction.support.TransactionTemplate tx=new org.springframework.transaction.support.TransactionTemplate(new ClassificationTransactions());
        when(access.execute(eq(session),eq(account),any())).thenAnswer(call->tx.execute(status->
                call.<Function<SessionAccess.Context,Object>>getArgument(2).apply(context)));
        when(access.executeForGroups(eq(session),eq(account),anyList(),any())).thenAnswer(call->tx.execute(status->
                call.<Function<SessionAccess.Context,Object>>getArgument(3).apply(context)));
        when(students.institutional(organization)).thenAnswer(call->{
            assertTrue(org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive());return false;
        });
        UUID recipient=UUID.randomUUID();
        when(canary.applies(organization,"file.share.view")).thenReturn(true);
        when(canary.checkContent(session,account,account,organization,group,"file.share.view",false)).thenAnswer(call->{
            assertFalse(org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive());return decision;
        });
        when(jdbc.query(anyString(),any(org.springframework.jdbc.core.RowMapper.class),any(byte[].class))).thenReturn(List.of(UUID.randomUUID()));
        when(professional.recipient(organization,group,recipient,"VIEW")).thenReturn(UUID.randomUUID());
        assertNotNull(service.professionalRecipient(caller,"Bearer delegated",
                new com.unidocs.auth.authorization.api.ProfessionalRecipientRequest(account,organization,group,recipient,"VIEW")));
        verify(students,times(2)).institutional(organization);
    }

    /** A tenant type change cannot reuse the first context's graph decision or enter recipient matching. */
    @Test void sharingRejectsTenantClassificationChangeBeforeRecipientEligibility() {
        when(students.institutional(organization)).thenReturn(false,true);
        when(canary.applies(organization,"file.share.view")).thenReturn(true);
        when(canary.checkContent(session,account,account,organization,group,"file.share.view",false)).thenReturn(decision);
        when(jdbc.query(anyString(),any(org.springframework.jdbc.core.RowMapper.class),any(byte[].class))).thenReturn(List.of(UUID.randomUUID()));
        when(access.executeForGroups(eq(session),eq(account),anyList(),any())).thenAnswer(call->
                call.<Function<SessionAccess.Context,Object>>getArgument(3).apply(context));
        OperationAuthorizationFailure failure=assertThrows(OperationAuthorizationFailure.class,()->service.professionalRecipient(
                caller,"Bearer delegated",new com.unidocs.auth.authorization.api.ProfessionalRecipientRequest(
                        account,organization,group,UUID.randomUUID(),"VIEW")));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE,failure.status());
        verify(canary,never()).revalidate(any(),any(),any(),any());
        verifyNoInteractions(professional);
    }

    /** Supplies real Spring synchronization/transaction boundaries without a database or extra infrastructure. */
    private static final class ClassificationTransactions extends org.springframework.transaction.support.AbstractPlatformTransactionManager {
        /** @return isolated test transaction marker */
        @Override protected Object doGetTransaction() {return new Object();}
        /** @param transaction marker @param definition transaction settings */
        @Override protected void doBegin(Object transaction,org.springframework.transaction.TransactionDefinition definition) { }
        /** @param status completed transaction */
        @Override protected void doCommit(org.springframework.transaction.support.DefaultTransactionStatus status) { }
        /** @param status rejected transaction */
        @Override protected void doRollback(org.springframework.transaction.support.DefaultTransactionStatus status) { }
    }

    /** @return the server-registered collaboration request for the selected tenant and group */
    private OperationAuthorizationRequest request() {
        return new OperationAuthorizationRequest(OPERATION, account, "GROUP", organization, group);
    }

    /**
     * Builds a token whose subject and expiry can be varied independently.
     * @param subject product account or service identity
     * @param expires token expiry
     * @return synthetic token consumed only by the mocked decoder
     */
    private Jwt jwt(String subject, Instant expires) {
        return Jwt.withTokenValue("synthetic").header("alg", "RS256").subject(subject)
                .claim("sid", session.toString()).issuedAt(now.minusSeconds(60)).expiresAt(expires).build();
    }
}
