package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.PermissionsServiceGrpc;
import com.authzed.grpcutil.BearerToken;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.authorization.application.ProfessionalAuthorizationService;
import com.unidocs.auth.authorization.application.ProfessionalSpiceDbCanary;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.junit.jupiter.api.Assertions.*;

/** Real pinned department witnesses with API-coordinated, fixture-recorded membership changes. */
@EnabledIfEnvironmentVariable(named="AUTH_PHASE5_SCOPE_ACCEPTANCE",matches="true")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SpiceDbPhase5AssignmentScopeTests {
    private JdbcTemplate jdbc;
    private DataSourceTransactionManager transactions;
    private ManagedChannel channel;
    private SessionAccess access;
    private ProfessionalSpiceDbCanary canary;
    private UUID organization,actor,recipient,department,team,session;

    /** Connects only to the existing test schema and the existing check gateway; no application is started. */
    @BeforeAll void connect() {
        for(String flag:java.util.List.of("AUTH_SPICEDB_PROJECTION_ENABLED","AUTH_SPICEDB_CANARY_ENABLED",
                "AUTH_SPICEDB_CANARY_MANAGEMENT_ENABLED","AUTH_SPICEDB_CANARY_ENFORCEMENT_ENABLED"))
            assertEquals("true",required(flag),"Assignment acceptance requires actual selected graph enforcement");
        String url=required("DB_URL");
        assertTrue(url.matches("jdbc:mysql://[^/]+/auth_service_test(?:\\?.*)?"));
        url=url.replaceAll("([?&])socketTimeout=[^&]*","$1socketTimeout=45000");
        if(!url.contains("socketTimeout="))url+=(url.contains("?")?"&":"?")+"socketTimeout=45000";
        DriverManagerDataSource source=new DriverManagerDataSource(url,required("DB_USERNAME"),required("DB_PASSWORD"));
        jdbc=new JdbcTemplate(source);jdbc.setQueryTimeout(30);
        transactions=new DataSourceTransactionManager(source);
        assertEquals("auth_service_test",jdbc.queryForObject("SELECT DATABASE()",String.class));
        assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM flyway_schema_history WHERE version='47' AND success=1",Integer.class));
        organization=id("AUTH_PHASE5_ORGANIZATION_ID");actor=id("AUTH_PHASE5_SCOPE_ACTOR_ACCOUNT_ID");
        recipient=id("AUTH_PHASE5_SCOPE_RECIPIENT_ACCOUNT_ID");department=id("AUTH_PHASE5_DEPARTMENT_ID");
        team=id("AUTH_PHASE5_TEAM_ID");session=id("AUTH_PHASE5_SCOPE_SESSION_ID");
        channel=ManagedChannelBuilder.forTarget(required("AUTH_SPICEDB_ENDPOINT")).usePlaintext().build();
        SpiceDbPermissionClient graph=new SpiceDbPermissionClient(PermissionsServiceGrpc.newBlockingStub(channel)
                .withCallCredentials(new BearerToken(required("AUTH_SPICEDB_PRESHARED_KEY"))),5000);
        SessionRepository sessions=new SessionRepository(jdbc,null);
        access=new SessionAccess(sessions,Clock.systemUTC(),transactions);
        OperationPolicyCatalogRepository policies=new OperationPolicyCatalogRepository(jdbc);
        DefaultListableBeanFactory beans=new DefaultListableBeanFactory();
        ProfessionalAuthorizationService professional=new ProfessionalAuthorizationService(jdbc,sessions,new OrganizationRepository(jdbc,null),
                policies,Clock.systemUTC(),beans.getBeanProvider(ProfessionalSpiceDbCanary.class));
        canary=new ProfessionalSpiceDbCanary(organization.toString(),false,true,true,access,professional,policies,graph,
                jdbc,Clock.systemUTC(),new SimpleMeterRegistry());beans.registerSingleton("canary",canary);
    }

    /**
     * Restores only recorded memberships through the host runner before each independent scenario.
     * @throws Exception when the bounded host-coordinated setup fails
     */
    @BeforeEach void restoreRecordedScope() throws Exception {
        marker("PHASE5_SCOPE_RESET");
        await(()->ready(false),40);
    }

    /** A department-only administrator proves one direct management scope without the legacy authority intersection. */
    @Test @Order(1) void directDepartmentResponsibilityProvesRecipientScope() {
        ProfessionalSpiceDbCanary.Decision decision=decision();
        assertEquals(department,decision.recipientScope().scope());
        assertEquals("ALLOWED",access.execute(session,actor,context->canary.revalidate(decision,context,actor,organization)).reasonCode());
    }

    /**
     * A committed recipient membership revocation invalidates evidence captured at the old graph revision.
     * @throws Exception when the bounded host-coordinated mutation fails
     */
    @Test @Order(2) void committedRecipientDepartmentRevocationRejectsOldProof() throws Exception {
        ProfessionalSpiceDbCanary.Decision decision=decision();
        marker("PHASE5_SCOPE_REVOKE_RECIPIENT");await(()->memberCount(recipient,false)==0,40);
        rejectWithoutWrites(decision);
    }

    /**
     * A committed actor membership revocation invalidates the same direct department witness.
     * @throws Exception when the bounded host-coordinated mutation fails
     */
    @Test @Order(3) void committedActorDepartmentRevocationRejectsOldProof() throws Exception {
        ProfessionalSpiceDbCanary.Decision decision=decision();
        marker("PHASE5_SCOPE_REVOKE_ACTOR");await(()->memberCount(actor,false)==0,40);
        rejectWithoutWrites(decision);
    }

    /**
     * A real actor department-membership deadline passes during a final SQL row-lock wait, independently of SQL authority matching.
     * @throws Exception when the bounded lock operation or host-coordinated setup fails
     */
    @Test @Order(4) void actorDepartmentExpiryDuringLockWaitRejectsOldProof() throws Exception {
        marker("PHASE5_SCOPE_EXPIRE_ACTOR");await(()->ready(true),40);
        ProfessionalSpiceDbCanary.Decision decision=decision();
        SessionAccess.Context context=access.execute(session,actor,current->current);
        Instant deadline=jdbc.queryForObject("SELECT valid_until FROM group_membership WHERE organization_id=? AND group_id=? "
                +"AND account_id=? AND status='ACTIVE' AND valid_until>UTC_TIMESTAMP(6)",java.sql.Timestamp.class,
                bytes(organization),bytes(department),bytes(actor)).toInstant();
        assertTrue(Duration.between(Instant.now(),deadline).toSeconds()<30,"Expiry fixture must be bounded");
        Map<String,Long> before=businessCounts();
        try(Connection blocker=jdbc.getDataSource().getConnection();
                java.util.concurrent.ExecutorService executor=Executors.newSingleThreadExecutor()) {
            blocker.setAutoCommit(false);
            try {
                try(PreparedStatement lock=blocker.prepareStatement("SELECT id FROM group_membership WHERE organization_id=? AND group_id=? "
                        +"AND account_id=? AND status='ACTIVE' FOR UPDATE")) {
                    lock.setBytes(1,bytes(organization));lock.setBytes(2,bytes(department));lock.setBytes(3,bytes(actor));
                    try(java.sql.ResultSet rows=lock.executeQuery()){assertTrue(rows.next());}
                }
                java.util.concurrent.Future<?> attempt=executor.submit(()->new org.springframework.transaction.support.TransactionTemplate(transactions)
                        .execute(status->{canary.revalidate(decision,context,actor,organization);fail("Expired department proof reached business work");return true;}));
                assertThrows(java.util.concurrent.TimeoutException.class,()->attempt.get(200,TimeUnit.MILLISECONDS));
                long wait=Duration.between(Instant.now(),deadline.plusMillis(100)).toMillis();
                if(wait>0)Thread.sleep(wait);
                blocker.rollback();
                java.util.concurrent.ExecutionException failure=assertThrows(java.util.concurrent.ExecutionException.class,
                        ()->attempt.get(15,TimeUnit.SECONDS));
                assertInstanceOf(OperationAuthorizationFailure.class,failure.getCause());
            } finally { blocker.rollback(); }
        }
        assertEquals(before,businessCounts(),"Expiry denial wrote membership, audit or business outbox records");
        await(this::projectionApplied,40);
    }

    /** @return graph evidence whose direct responsibility can only be witnessed at the recorded department */
    private ProfessionalSpiceDbCanary.Decision decision() {
        ProfessionalSpiceDbCanary.Decision decision=canary.checkAssignment(session,actor,actor,organization,team,recipient,"organization.group.assign");
        assertEquals(department,decision.recipientScope().scope());return decision;
    }

    /** @param decision old pinned scope evidence */
    private void rejectWithoutWrites(ProfessionalSpiceDbCanary.Decision decision) {
        Map<String,Long> before=businessCounts();
        OperationAuthorizationFailure failure=assertThrows(OperationAuthorizationFailure.class,()->access.execute(session,actor,context->{
            canary.revalidate(decision,context,actor,organization);
            fail("Revoked scope proof reached business work");return true;
        }));
        assertTrue(failure.status()==HttpStatus.FORBIDDEN||failure.status()==HttpStatus.SERVICE_UNAVAILABLE);
        assertEquals(before,businessCounts(),"Revoked scope evidence wrote business/audit/outbox state");
    }

    /** @return stable business record counts, excluding background outbox publication metadata */
    private Map<String,Long> businessCounts() {
        return Map.of("memberships",jdbc.queryForObject("SELECT COUNT(*) FROM group_membership WHERE organization_id=?",Long.class,bytes(organization)),
                "audit",jdbc.queryForObject("SELECT COUNT(*) FROM iam_professional_audit WHERE organization_id=?",Long.class,bytes(organization)),
                "outbox",jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE aggregate_id=?",Long.class,bytes(organization)));
    }

    /** @param expiring whether setup requires a future temporary actor membership @return current source/projection admission */
    private boolean ready(boolean expiring) {
        return memberCount(actor,expiring)==1&&memberCount(recipient,false)==1&&projectionApplied();
    }

    /** @return whether the automatic worker has acknowledged every current source and scheduled transition */
    private boolean projectionApplied() {
        return jdbc.queryForObject(
                "SELECT COUNT(*) FROM spicedb_organization_sync_state s JOIN organization o ON o.id=s.organization_id "
                +"WHERE s.organization_id=? AND s.sync_status='APPLIED' AND s.required_revision=s.applied_revision "
                +"AND s.required_source_version=s.applied_source_version AND s.required_source_version=o.authorization_version "
                +"AND (s.next_boundary_at IS NULL OR s.next_boundary_at>UTC_TIMESTAMP(6))",Integer.class,bytes(organization))==1;
    }

    /** @param account actor or recipient @param expiring whether the row must have a future deadline @return eligible current row count */
    private int memberCount(UUID account,boolean expiring) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM group_membership WHERE organization_id=? AND group_id=? AND account_id=? "
                +"AND status='ACTIVE' AND valid_from<=UTC_TIMESTAMP(6) AND "+(expiring?"valid_until>UTC_TIMESTAMP(6)":"(valid_until IS NULL OR valid_until>UTC_TIMESTAMP(6))"),
                Integer.class,bytes(organization),bytes(department),bytes(account));
    }

    /** @param condition required database fact @param seconds bounded external setup budget @throws Exception on interruption or timeout */
    private void await(java.util.function.BooleanSupplier condition,int seconds) throws Exception {
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds);
        while(System.nanoTime()<end){if(condition.getAsBoolean())return;Thread.sleep(100);}
        fail("Host-coordinated scope setup did not complete within its bounded window");
    }

    /** @param value fixed local test coordination label, containing no credential or caller-controlled text */
    private void marker(String value){System.out.println(value);System.out.flush();}
    /** Closes only this test's gateway connection. */
    @AfterAll void disconnect(){if(channel!=null)channel.shutdownNow();}
    /** @param key required test fixture setting @return UUID value */
    private static UUID id(String key){return UUID.fromString(required(key));}
    /** @param key required test setting @return nonblank value without credential-bearing diagnostics */
    private static String required(String key){String value=System.getenv(key);if(value==null||value.isBlank())throw new IllegalArgumentException("Missing "+key);return value;}
}
