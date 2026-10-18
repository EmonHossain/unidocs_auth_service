package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.*;
import com.authzed.grpcutil.BearerToken;
import com.unidocs.auth.authorization.application.*;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import com.unidocs.auth.group.application.GroupAuthority;
import com.unidocs.auth.group.persistence.GroupRepository;
import com.unidocs.auth.group.persistence.GroupRuleRepository;
import com.unidocs.auth.organization.persistence.OrganizationRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Explicit live acceptance on existing shared services; never starts an application, container or schema. */
@EnabledIfEnvironmentVariable(named="AUTH_PHASE5_LIVE_ACCEPTANCE",matches="true")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SpiceDbPhase5LiveAcceptanceTests {
    private JdbcTemplate jdbc;
    private SpiceDbOrganizationSyncService sync;
    private SpiceDbRelationshipWriter writer;
    private SpiceDbPermissionClient graph;
    private ManagedChannel channel;
    private UUID organization;
    private UUID actor;
    private UUID employee;
    private UUID group;
    private UUID session;
    private SessionAccess access;
    private ProfessionalSpiceDbCanary canary;
    private GroupAuthority authority;
    private DataSourceTransactionManager transactions;
    private final Set<UUID> ownedLeases=new HashSet<>();

    /** Connects only to the existing test schema while automatic projection and enforcement are disabled. */
    @BeforeAll
    void connect() {
        for(String flag:List.of("AUTH_SPICEDB_PROJECTION_ENABLED","AUTH_SPICEDB_CANARY_ENABLED",
                "AUTH_SPICEDB_CANARY_MANAGEMENT_ENABLED","AUTH_SPICEDB_CANARY_ENFORCEMENT_ENABLED"))
            assertEquals("false",required(flag),"Live acceptance requires stopped automatic workers and enforcement");
        String url=required("DB_URL");
        assertTrue(url.matches("jdbc:mysql://[^/]+/auth_service_test(?:\\?.*)?"),"Only the existing Auth test schema is supported");
        DriverManagerDataSource source=new DriverManagerDataSource(url,required("DB_USERNAME"),required("DB_PASSWORD"));
        jdbc=new JdbcTemplate(source);
        jdbc.setQueryTimeout(10);
        assertEquals("auth_service_test",jdbc.queryForObject("SELECT DATABASE()",String.class));
        assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM flyway_schema_history WHERE version='46' AND success=1",Integer.class));
        assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM flyway_schema_history WHERE version='47' AND success=1",Integer.class));
        organization=UUID.fromString(required("AUTH_PHASE5_ORGANIZATION_ID"));
        actor=UUID.fromString(required("AUTH_PHASE5_ACTOR_ACCOUNT_ID"));
        employee=UUID.fromString(required("AUTH_PHASE5_TARGET_ACCOUNT_ID"));
        group=UUID.fromString(required("AUTH_PHASE5_TEAM_ID"));
        session=UUID.fromString(required("AUTH_PHASE5_SESSION_ID"));
        channel=ManagedChannelBuilder.forTarget(required("AUTH_SPICEDB_ENDPOINT")).usePlaintext().build();
        PermissionsServiceGrpc.PermissionsServiceBlockingStub stub=PermissionsServiceGrpc.newBlockingStub(channel);
        graph=new SpiceDbPermissionClient(stub.withCallCredentials(new BearerToken(required("AUTH_SPICEDB_PRESHARED_KEY"))),5000);
        writer=new SpiceDbRelationshipWriter(stub.withCallCredentials(new BearerToken(required("AUTH_SPICEDB_PROJECTION_PRESHARED_KEY"))),5000,1000);
        transactions=new DataSourceTransactionManager(source);
        sync=new SpiceDbOrganizationSyncService(jdbc,transactions,new SpiceDbOrganizationSyncProperties(
                true,required("AUTH_SPICEDB_ENDPOINT"),required("AUTH_SPICEDB_PROJECTION_PRESHARED_KEY"),true,5000,1000,1,300,5000));
        SessionRepository sessions=new SessionRepository(jdbc,null);
        access=new SessionAccess(sessions,Clock.systemUTC(),transactions);
        OrganizationRepository organizations=new OrganizationRepository(jdbc,null);
        OperationPolicyCatalogRepository policies=new OperationPolicyCatalogRepository(jdbc);
        DefaultListableBeanFactory beans=new DefaultListableBeanFactory();
        ProfessionalAuthorizationService professional=new ProfessionalAuthorizationService(jdbc,sessions,organizations,
                policies,Clock.systemUTC(),beans.getBeanProvider(ProfessionalSpiceDbCanary.class));
        canary=new ProfessionalSpiceDbCanary(organization.toString(),false,true,true,access,professional,policies,graph,
                jdbc,Clock.systemUTC(),new SimpleMeterRegistry());
        beans.registerSingleton("canary",canary);
        authority=new GroupAuthority(sessions,new GroupRepository(jdbc,null),new GroupRuleRepository(jdbc),organizations,
                professional,beans.getBeanProvider(ProfessionalSpiceDbCanary.class));
        reconcile(writer);
    }

    /** Reconciles V46, then replays duplicate/out-of-order notifications without changing any business ACL. */
    @Test @Order(5)
    void realGatewayReconciliationAndNotificationReplayPreserveParity() {
        reconcile(writer);
        assertParity();
        long source=jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(organization));
        new org.springframework.transaction.support.TransactionTemplate(
                new DataSourceTransactionManager(jdbc.getDataSource())).executeWithoutResult(status->{
            com.unidocs.auth.outbox.persistence.OutboxRepository outbox=new com.unidocs.auth.outbox.persistence.OutboxRepository(jdbc);
            for(long version:new long[]{source,Math.max(0,source-1),source})
                outbox.lifecycle("ORGANIZATION",organization,version,"PHASE5_PROJECTION_REPLAY",null,organization,null,Instant.now());
        });
        reconcile(writer);
        assertParity();
    }

    /** A real second batch commits remotely but loses its acknowledgement; replay must recover under the fence. */
    @Test @Order(6)
    void lostSecondBatchAcknowledgementAndSupersessionRecoverWithoutStaleAllow() {
        SpiceDbRelationshipWriter interrupted=mock(SpiceDbRelationshipWriter.class);
        AtomicInteger batches=new AtomicInteger();
        doAnswer(call->{
            String token=writer.writeRelationships(call.getArgument(0));
            if(batches.incrementAndGet()==2)throw new IllegalStateException("Simulated lost committed acknowledgement");
            return token;
        }).when(interrupted).writeRelationships(anyList());
        UUID lease=lease();
        try {
            assertThrows(IllegalStateException.class,()->sync.synchronizeOrganization(organization,lease,interrupted,Instant.now()));
        } finally { sync.recordSyncFailure(organization,lease,Instant.now(),"ACCEPTANCE_LOST_ACK"); }
        assertEquals(2,batches.get());
        assertPending();
        reconcile(writer);
        SpiceDbRelationshipWriter superseded=mock(SpiceDbRelationshipWriter.class);
        AtomicInteger writes=new AtomicInteger();
        doAnswer(call->{
            String token=writer.writeRelationships(call.getArgument(0));
            if(writes.incrementAndGet()==1)queue();
            return token;
        }).when(superseded).writeRelationships(anyList());
        try {
            reconcile(superseded);
            assertEquals(1,writes.get(),"Superseded workers must stop before another gateway batch");
            assertPending();
        } finally { reconcile(writer); }
        assertParity();
    }

    /** Exercises the actual manager/catalog boundary with real IAM locks and pinned gateway evidence. */
    @Test @Order(3)
    void directManagerAndCatalogEntryRequireCurrentGraphEvidence() {
        ProfessionalSpiceDbCanary.Decision manager=canary.check(session,actor,actor,organization,group,"team.access.update");
        assertNotNull(access.execute(session,actor,context->authority.require(context,actor,organization,group,
                false,true,false,true,manager)));
        ProfessionalSpiceDbCanary.Decision catalog=canary.check(session,actor,actor,organization,"organization.group.create");
        assertNotNull(access.execute(session,actor,context->authority.requireCatalog(context,actor,organization,group,false,catalog)));
        assertThrows(OperationAuthorizationFailure.class,()->access.execute(session,actor,
                context->authority.require(context,actor,organization,group,false,true,false)));
    }

    /**
     * A concurrent, real logout commits after graph preflight; final application admission must write nothing.
     * @throws Exception when a bounded logout or worker task fails
     */
    @Test @Order(1)
    void concurrentSessionRevocationBetweenPreflightAndBusinessCommitDeniesWithoutWrites() throws Exception {
        UUID race=UUID.fromString(required("AUTH_PHASE5_RACE_SESSION_ID"));
        ProfessionalSpiceDbCanary.Decision decision=canary.check(race,actor,actor,organization,"organization.group.create");
        List<Map<String,Object>> before=businessState();
        try(java.util.concurrent.ExecutorService executor=Executors.newSingleThreadExecutor()) {
            int status=executor.submit(()->HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build().send(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:8080/api/v1/auth/logout"))
                    .timeout(Duration.ofSeconds(15)).header("Authorization","Bearer "+required("AUTH_PHASE5_RACE_TOKEN"))
                    .POST(HttpRequest.BodyPublishers.noBody()).build(),HttpResponse.BodyHandlers.discarding()).statusCode())
                    .get(20,TimeUnit.SECONDS);
            assertEquals(204,status);
        }
        assertEquals("REVOKED",jdbc.queryForObject("SELECT status FROM user_session WHERE id=?",String.class,bytes(race)));
        assertEquals(0,jdbc.queryForObject("SELECT COUNT(*) FROM session_account_grant WHERE session_id=? AND status='ACTIVE'",Integer.class,bytes(race)));
        assertThrows(com.unidocs.auth.authentication.application.AuthenticationFailure.class,()->access.execute(race,actor,context->{
            canary.revalidate(decision,context,actor,organization);
            jdbc.update("UPDATE group_rule SET version=version+1 WHERE organization_id=? AND group_id=?",bytes(organization),bytes(group));
            fail("A revoked session reached business mutation");
            return true;
        }));
        assertEquals(before,businessState(),"Revoked admission changed business state");
    }

    /**
     * A real selected-grant deadline passes while final SQL waits for another connection's row lock.
     * @throws Exception when a bounded SQL or worker task fails
     */
    @Test @Order(2)
    void selectedGrantExpiryDuringConcurrentRowLockWaitDeniesWithoutBusinessWrites() throws Exception {
        UUID expiring=UUID.fromString(required("AUTH_PHASE5_EXPIRY_SESSION_ID"));
        ProfessionalSpiceDbCanary.Decision decision=canary.check(expiring,actor,actor,organization,"organization.group.create");
        SessionAccess.Context context=access.execute(expiring,actor,current->current);
        List<Map<String,Object>> before=businessState();
        try(java.sql.Connection blocker=jdbc.getDataSource().getConnection();
                java.util.concurrent.ExecutorService executor=Executors.newSingleThreadExecutor()) {
            blocker.setAutoCommit(false);
            Instant deadline=Instant.now().plusSeconds(2);
            try {
                try(java.sql.PreparedStatement update=blocker.prepareStatement("UPDATE session_account_grant SET idle_expires_at=? WHERE session_id=? AND account_id=?")) {
                    update.setTimestamp(1,java.sql.Timestamp.from(deadline));update.setBytes(2,bytes(expiring));update.setBytes(3,bytes(actor));
                    assertEquals(1,update.executeUpdate());
                }
                java.util.concurrent.CountDownLatch started=new java.util.concurrent.CountDownLatch(1);
                java.util.concurrent.Future<?> finalTransaction=executor.submit(()->{
                    started.countDown();
                    return new org.springframework.transaction.support.TransactionTemplate(transactions).execute(status->{
                        canary.revalidate(decision,context,actor,organization);
                        jdbc.update("UPDATE group_rule SET version=version+1 WHERE organization_id=? AND group_id=?",bytes(organization),bytes(group));
                        fail("Expired selected grant reached business mutation");return true;
                    });
                });
                assertTrue(started.await(2,TimeUnit.SECONDS));
                assertThrows(java.util.concurrent.TimeoutException.class,()->finalTransaction.get(200,TimeUnit.MILLISECONDS));
                long wait=Duration.between(Instant.now(),deadline.plusMillis(100)).toMillis();
                if(wait>0)Thread.sleep(Math.min(wait,3000));
                blocker.commit();
                java.util.concurrent.ExecutionException failure=assertThrows(java.util.concurrent.ExecutionException.class,
                        ()->finalTransaction.get(10,TimeUnit.SECONDS));
                assertInstanceOf(OperationAuthorizationFailure.class,failure.getCause());
                assertEquals(org.springframework.http.HttpStatus.FORBIDDEN,((OperationAuthorizationFailure)failure.getCause()).status());
            } finally { blocker.rollback(); }
        }
        assertEquals(before,businessState(),"Expiry during lock wait changed business state");
    }

    /**
     * A committed projection revision supersedes a real pinned decision for each registered management family.
     * @param operation server-selected operation
     * @throws Exception when the bounded competing revision update fails
     */
    @org.junit.jupiter.params.ParameterizedTest @Order(4)
    @org.junit.jupiter.params.provider.ValueSource(strings={"organization.group.create","organization.employee.create",
            "organization.employee.remove","organization.employee.reset","organization.responsibility.assign",
            "organization.access.update","organization.department.assign","organization.group.assign",
            "organization.group.unassign","department.access.update","team.access.update","organization.collaboration.invite"})
    void committedProjectionChangeRejectsEveryManagementDecision(String operation) throws Exception {
        UUID scope=operation.equals("organization.department.assign")||operation.equals("department.access.update")
                ?UUID.fromString(required("AUTH_PHASE5_DEPARTMENT_ID"))
                :Set.of("organization.group.assign","organization.group.unassign","team.access.update",
                        "organization.collaboration.invite").contains(operation)?group:null;
        ProfessionalSpiceDbCanary.Decision decision=canary.check(session,actor,actor,organization,scope,operation);
        List<Map<String,Object>> before=businessState();
        try(java.util.concurrent.ExecutorService executor=Executors.newSingleThreadExecutor()) {
            executor.submit(this::queue).get(5,TimeUnit.SECONDS);
            OperationAuthorizationFailure failure=assertThrows(OperationAuthorizationFailure.class,()->access.execute(session,actor,context->{
                canary.revalidate(decision,context,actor,organization);
                jdbc.update("UPDATE group_rule SET version=version+1 WHERE organization_id=? AND group_id=?",bytes(organization),bytes(group));
                fail("A superseded graph decision reached business mutation");return true;
            }));
            assertEquals(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE,failure.status());
            assertEquals(before,businessState(),"Superseded graph evidence changed business state");
        } finally { reconcile(writer); }
    }

    /** Checks every projected capability for both recorded actors against an independent inheritance evaluator. */
    private void assertParity() {
        List<SpiceDbRelationship> tuples=jdbc.query("SELECT resource_type,resource_id,relation_name,subject_type,subject_id "
                +"FROM spicedb_organization_sync_tuple WHERE organization_id=?",(row,index)->new SpiceDbRelationship(
                row.getString(1),row.getString(2),row.getString(3),row.getString(4),row.getString(5)),bytes(organization));
        assertFalse(tuples.isEmpty());
        Set<String> capabilities=new TreeSet<>();
        for(SpiceDbRelationship tuple:tuples)if(tuple.resourceType().equals("scope_capability"))capabilities.add(tuple.resourceId());
        assertTrue(capabilities.size()<2000,"Acceptance projection unexpectedly exceeds bounded fixture size");
        ZedToken snapshot=check("organization",organization.toString(),"member",actor,null).getCheckedAt();
        assertFalse(snapshot.getToken().isBlank());
        for(UUID account:List.of(actor,employee))for(String capability:capabilities)
            for(String relation:List.of("category_grantee","scoped_grantee","responsibility_grantee")) {
                boolean expected=relation.equals("responsibility_grantee")
                        ?tuples.contains(new SpiceDbRelationship("scope_capability",capability,relation,"account",account.toString()))
                        :inherited(tuples,capability,relation,account.toString(),new HashSet<>());
                String permission=switch(relation) {
                    case "category_grantee"->"category_grant";
                    case "responsibility_grantee"->"responsibility_grant";
                    default->"scoped_grant";
                };
                CheckPermissionResponse actual=check("scope_capability",capability,
                        permission,account,snapshot);
                assertEquals(snapshot,actual.getCheckedAt());
                assertTrue(actual.getPermissionship()==CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION
                        || actual.getPermissionship()==CheckPermissionResponse.Permissionship.PERMISSIONSHIP_NO_PERMISSION,
                        "Conditional or incomplete permission evidence must fail closed");
                assertEquals(expected,actual.getPermissionship()==CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION,
                        "Projected same-authority inheritance differs from the acknowledged ledger");
            }
        Map<String,Object> state=jdbc.queryForMap("SELECT required_revision,applied_revision,required_source_version,"
                +"applied_source_version,sync_status FROM spicedb_organization_sync_state WHERE organization_id=?",bytes(organization));
        assertEquals(state.get("required_revision"),state.get("applied_revision"));
        assertEquals(state.get("required_source_version"),state.get("applied_source_version"));
        assertEquals("APPLIED",state.get("sync_status"));
    }

    /** @param tuples acknowledged relationships @param scope capability @param relation exact grant layer
     * @param account existing account @param visited cycle guard @return inherited same-authority membership */
    private boolean inherited(List<SpiceDbRelationship> tuples,String scope,String relation,String account,Set<String> visited) {
        if(!visited.add(scope))return false;
        for(SpiceDbRelationship tuple:tuples)if(tuple.resourceType().equals("scope_capability")&&tuple.resourceId().equals(scope)) {
            if(tuple.relation().equals(relation)&&tuple.subjectType().equals("account")&&tuple.subjectId().equals(account))return true;
            if(tuple.relation().equals("parent")&&inherited(tuples,tuple.subjectId(),relation,account,visited))return true;
        }
        return false;
    }

    /** @param type graph resource type @param id resource ID @param permission allowed check @param account subject
     * @param snapshot optional pinned snapshot @return bounded graph response */
    private CheckPermissionResponse check(String type,String id,String permission,UUID account,ZedToken snapshot) {
        return graph.checkPermission(CheckPermissionRequest.newBuilder().setResource(ObjectReference.newBuilder().setObjectType(type).setObjectId(id))
                .setPermission(permission).setSubject(SubjectReference.newBuilder().setObject(ObjectReference.newBuilder()
                        .setObjectType("account").setObjectId(account.toString())))
                .setConsistency(snapshot==null?Consistency.newBuilder().setFullyConsistent(true).build():
                        Consistency.newBuilder().setAtExactSnapshot(snapshot).build()).build());
    }

    /** @return unchanged group-rule rows, containing no credential or session secrets */
    private List<Map<String,Object>> businessState() {
        return jdbc.queryForList("SELECT HEX(group_id) id,version,discovery_scope,join_rule FROM group_rule WHERE organization_id=? ORDER BY group_id",bytes(organization));
    }

    /** Queues a monotonic projection revision without changing business ACL facts. */
    private void queue() {
        assertEquals(1,jdbc.update("UPDATE spicedb_organization_sync_state SET required_revision=required_revision+1,"
                +"sync_status='PENDING',available_at=UTC_TIMESTAMP(6) WHERE organization_id=?",bytes(organization)));
    }

    /** @return explicit current-worker lease after fencing the organization */
    private UUID lease() {
        queue();
        UUID lease=UUID.randomUUID();
        assertEquals(1,jdbc.update("UPDATE spicedb_organization_sync_state SET lease_owner=?,lease_until=TIMESTAMPADD(SECOND,300,UTC_TIMESTAMP(6)) "
                +"WHERE organization_id=? AND lease_owner IS NULL",bytes(lease),bytes(organization)));
        ownedLeases.add(lease);
        return lease;
    }

    /** @param selectedWriter real gateway writer or fault-injecting forwarding writer */
    private void reconcile(SpiceDbRelationshipWriter selectedWriter) {
        sync.synchronizeOrganization(organization,lease(),selectedWriter,Instant.now());
    }

    /** Requires a stale/partial pass to remain fenced without printing tokens. */
    private void assertPending() {
        assertEquals("PENDING",jdbc.queryForObject("SELECT sync_status FROM spicedb_organization_sync_state WHERE organization_id=?",String.class,bytes(organization)));
        assertEquals(0,jdbc.queryForObject("SELECT COUNT(*) FROM spicedb_organization_sync_state WHERE organization_id=? "
                +"AND required_revision=applied_revision",Integer.class,bytes(organization)));
    }

    /** Reconciles remaining owned test leases against current source facts and closes the gateway channel. */
    @AfterAll
    void disconnect() {
        try {
            if(sync!=null&&!ownedLeases.isEmpty()) {
                for(UUID lease:new ArrayList<>(ownedLeases))
                    sync.recordSyncFailure(organization,lease,Instant.now(),"ACCEPTANCE_CLEANUP");
                reconcile(writer);
                assertEquals("APPLIED",jdbc.queryForObject("SELECT sync_status FROM spicedb_organization_sync_state WHERE organization_id=?",
                        String.class,bytes(organization)),"Live acceptance cleanup did not reconcile current source facts");
            }
        } finally { if(channel!=null)channel.shutdownNow(); }
    }

    /** @param key explicit test configuration @return nonblank value without secret-bearing diagnostics */
    private static String required(String key) {
        String value=System.getenv(key);
        if(value==null||value.isBlank())throw new IllegalArgumentException("Missing Phase 5 acceptance setting: "+key);
        return value;
    }
}
