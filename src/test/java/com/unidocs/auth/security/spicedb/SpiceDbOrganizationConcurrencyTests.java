package com.unidocs.auth.security.spicedb;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import com.unidocs.auth.outbox.persistence.OutboxRepository;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Opt-in, rollback-only lock tests against the existing shared schema; no application or container is started. */
@EnabledIfEnvironmentVariable(named = "AUTH_PHASE5_SHARED_DATABASE_TESTS", matches = "true")
class SpiceDbOrganizationConcurrencyTests {
    private DriverManagerDataSource dataSource;
    private JdbcTemplate jdbc;
    private SpiceDbOrganizationSyncService sync;
    private UUID organization;

    /** An older domain context cannot rewind activity or the captured idle deadline, or reactivate a revoked grant. */
    @Test
    void earlierActivityCannotShortenCompletionDeadlineOrReactivateGrant() {
        UUID actor=UUID.fromString(required("AUTH_PHASE5_ACTOR_ACCOUNT_ID"));
        UUID session=UUID.fromString(jdbc.queryForObject("SELECT BIN_TO_UUID(s.id) FROM user_session s JOIN session_account_grant g "
                +"ON g.session_id=s.id AND g.account_id=s.login_account_id WHERE s.login_account_id=? "
                +"AND s.status='REVOKED' AND g.status='REVOKED' ORDER BY s.id DESC LIMIT 1",String.class,bytes(actor)));
        String sessionSql="SELECT status,last_activity_at FROM user_session WHERE id=?";
        String grantSql="SELECT status,last_activity_at,idle_expires_at,absolute_expires_at FROM session_account_grant WHERE session_id=? AND account_id=?";
        Map<String,Object> beforeSession=jdbc.queryForMap(sessionSql,bytes(session));
        Map<String,Object> beforeGrant=jdbc.queryForMap(grantSql,bytes(session),bytes(actor));
        try {
            new TransactionTemplate(new DataSourceTransactionManager(dataSource)).executeWithoutResult(status->{
                status.setRollbackOnly();
                com.unidocs.auth.session.persistence.SessionRepository sessions=new com.unidocs.auth.session.persistence.SessionRepository(jdbc,null);
                com.unidocs.auth.session.domain.SessionGrantPolicy policy=sessions.policy();
                Instant recent=Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MICROS);
                Instant absolute=recent.plus(policy.absoluteTimeout()),captured=policy.idleExpiry(recent,absolute);
                jdbc.update("UPDATE user_session SET last_activity_at=? WHERE id=?",java.sql.Timestamp.from(recent),bytes(session));
                jdbc.update("UPDATE session_account_grant SET last_activity_at=?,idle_expires_at=?,absolute_expires_at=? WHERE session_id=? AND account_id=?",
                        java.sql.Timestamp.from(recent),java.sql.Timestamp.from(captured),java.sql.Timestamp.from(absolute),bytes(session),bytes(actor));
                com.unidocs.auth.session.domain.UserSession current=sessions.lock(session).orElseThrow();
                com.unidocs.auth.session.domain.SessionAccountGrant grant=new com.unidocs.auth.session.domain.SessionAccountGrant(
                        session,actor,"REVOKED","LOGIN",1,captured,absolute);
                sessions.touch(current,grant,recent.minusSeconds(60));
                assertEquals(recent,jdbc.queryForObject("SELECT last_activity_at FROM user_session WHERE id=?",
                        java.sql.Timestamp.class,bytes(session)).toInstant());
                Map<String,Object> after=jdbc.queryForMap(grantSql,bytes(session),bytes(actor));
                assertEquals(recent,jdbc.queryForObject("SELECT last_activity_at FROM session_account_grant WHERE session_id=? AND account_id=?",
                        java.sql.Timestamp.class,bytes(session),bytes(actor)).toInstant());
                assertEquals(captured,jdbc.queryForObject("SELECT idle_expires_at FROM session_account_grant WHERE session_id=? AND account_id=?",
                        java.sql.Timestamp.class,bytes(session),bytes(actor)).toInstant());
                assertEquals("REVOKED",after.get("status"));
            });
        } finally {
            assertEquals(beforeSession,jdbc.queryForMap(sessionSql,bytes(session)));
            assertEquals(beforeGrant,jdbc.queryForMap(grantSql,bytes(session),bytes(actor)));
        }
    }

    /** Verifies real SQL scope matching cannot combine ALL_OF witnesses from separate managed scopes. */
    @Test
    void recipientAllOfRequiresOneCompleteCurrentManagedScope() {
        rollbackVerified(()->{
            Instant now=Instant.now();
            UUID actor=UUID.fromString(required("AUTH_PHASE5_ACTOR_ACCOUNT_ID"));
            UUID target=UUID.fromString(required("AUTH_PHASE5_TARGET_ACCOUNT_ID"));
            UUID department=UUID.fromString(required("AUTH_PHASE5_DEPARTMENT_ID"));
            UUID team=UUID.fromString(required("AUTH_PHASE5_TEAM_ID"));
            UUID organizationRole=role("ORG_ADMIN"),departmentRole=role("DEPARTMENT_ADMIN");
            UUID first=authority("organization.group.assign"),second=authority("organization.group.unassign");
            jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR UPDATE",Long.class);
            jdbc.update("UPDATE iam_professional_assignment SET status='REVOKED' WHERE organization_id=? AND account_id=?",
                    bytes(organization),bytes(actor));
            assignResponsibility(actor,null,organizationRole,now);
            assignResponsibility(actor,department,departmentRole,now);
            activateDepartmentMember(actor,department,now);
            activateDepartmentMember(target,department,now);
            assertEquals(1,jdbc.update("DELETE FROM iam_role_authority WHERE role_id=? AND authority_id=?",bytes(organizationRole),bytes(second)));
            assertEquals(1,jdbc.update("DELETE FROM iam_role_authority WHERE role_id=? AND authority_id=?",bytes(departmentRole),bytes(first)));
            com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository catalog=
                    mock(com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository.class);
            com.unidocs.auth.authorization.domain.OperationPolicySnapshot policy=new com.unidocs.auth.authorization.domain.OperationPolicySnapshot(
                    UUID.randomUUID(),"auth-service","organization.group.assign",1,UUID.randomUUID(),1,"ORGANIZATION",1,organizationRole,1,
                    new com.unidocs.auth.authorization.domain.OperationAuthorityPolicy(java.util.Set.of(first,second),
                            com.unidocs.auth.authorization.domain.AuthorityMatchMode.ALL_OF,true),java.util.Set.of(first,second),Map.of(first,1L,second,1L));
            when(catalog.findCurrent("auth-service","organization.group.assign","ORGANIZATION")).thenReturn(java.util.Optional.of(policy));
            com.unidocs.auth.authorization.application.ProfessionalAuthorizationService authorization=
                    new com.unidocs.auth.authorization.application.ProfessionalAuthorizationService(jdbc,
                            mock(com.unidocs.auth.session.persistence.SessionRepository.class),
                            mock(com.unidocs.auth.organization.persistence.OrganizationRepository.class),catalog,java.time.Clock.systemUTC());
            com.unidocs.auth.session.application.SessionAccess.Context context=mock(com.unidocs.auth.session.application.SessionAccess.Context.class);
            assertThrows(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class,
                    ()->authorization.assignmentRecipient(context,actor,organization,team,target,"organization.group.assign"));
            assertEquals(1,jdbc.update("INSERT INTO iam_role_authority(role_id,authority_id) VALUES(?,?)",bytes(departmentRole),bytes(first)));
            assertDoesNotThrow(()->authorization.assignmentRecipient(context,actor,organization,team,target,"organization.group.assign"));
            assertEquals(1,jdbc.update("UPDATE group_membership SET membership_type='TEMPORARY',valid_until=? WHERE organization_id=? AND group_id=? AND account_id=? AND status='ACTIVE'",
                    java.sql.Timestamp.from(now.minusSeconds(1)),bytes(organization),bytes(department),bytes(target)));
            assertThrows(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class,
                    ()->authorization.assignmentRecipient(context,actor,organization,team,target,"organization.group.assign"));
            activateDepartmentMember(target,department,now);
            SpiceDbRelationship grant=new SpiceDbRelationship("scope_capability",compact(department)+compact(second),
                    "scoped_grantee","account",actor.toString());
            SpiceDbRelationship direct=new SpiceDbRelationship("scope_capability",compact(department)+compact(second),
                    "responsibility_grantee","account",actor.toString());
            assertTrue(projected(now).contains(grant));
            assertTrue(projected(now).contains(direct));
            assertEquals(1,jdbc.update("UPDATE iam_group SET type='TEAM' WHERE organization_id=? AND id=?",bytes(organization),bytes(department)));
            assertFalse(projected(now).contains(grant));
            assertFalse(projected(now).contains(direct));
            assertThrows(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class,
                    ()->authorization.assignmentRecipient(context,actor,organization,team,target,"organization.group.assign"));
        });
    }

    /** Exercises tenant eligibility and retired-authority cleanup through the real snapshot SQL. */
    @Test
    void projectionExcludesWrongTenantAccountTypesAndRetiredAuthorities() {
        rollbackVerified(()->{
            UUID actor=UUID.fromString(required("AUTH_PHASE5_ACTOR_ACCOUNT_ID"));
            Instant now=Instant.now();
            SpiceDbRelationship member=new SpiceDbRelationship("organization",organization.toString(),"account_member","account",actor.toString());
            assertTrue(projected(now).contains(member));
            String original=jdbc.queryForObject("SELECT type FROM user_account WHERE id=?",String.class,bytes(actor));
            assertEquals(1,jdbc.update("UPDATE user_account SET type=? WHERE id=?",original.equals("COMPANY")?"CUSTOM":"COMPANY",bytes(actor)));
            java.util.Set<SpiceDbRelationship> mismatched=projected(now);
            assertFalse(mismatched.contains(member));
            assertTrue(mismatched.stream().noneMatch(tuple->tuple.subjectType().equals("account") && tuple.subjectId().equals(actor.toString())));
            jdbc.update("UPDATE user_account SET type=? WHERE id=?",original,bytes(actor));
            UUID authority=authority("organization.group.assign");
            SpiceDbRelationship grant=new SpiceDbRelationship("scope_capability",compact(organization)+compact(authority),
                    "scoped_grantee","account",actor.toString());
            assertTrue(projected(now).contains(grant));
            assertEquals(1,jdbc.update("UPDATE iam_authority SET status='RETIRED' WHERE id=?",bytes(authority)));
            assertFalse(projected(now).contains(grant));
        });
    }

    /**
     * Executes reconciliation migrations only inside rollback and preserves all applied/lease/intent evidence.
     * @param resource current eligibility or direct-responsibility migration resource
     */
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings={"V46__spicedb_coherent_scope_reprojection.sql",
            "V47__spicedb_direct_responsibility_reprojection.sql"})
    void reconciliationQueuesReprojectionWithoutDiscardingAppliedStateOrTupleIntent(String resource) {
        rollbackVerified(()->{
            Map<String,Object> before=state();
            List<Map<String,Object>> tuples=ledger();
            try {
                String sql=new org.springframework.core.io.ClassPathResource("db/migration/"+resource)
                        .getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
                assertTrue(jdbc.update(sql)>0);
            } catch(java.io.IOException failure) { throw new AssertionError("Reconciliation migration resource is unavailable",failure); }
            Map<String,Object> pending=state();
            assertEquals(((Number)before.get("required_revision")).longValue()+1,((Number)pending.get("required_revision")).longValue());
            assertEquals("PENDING",pending.get("sync_status"));
            for(String column:List.of("required_source_version","applied_revision","applied_source_version","zed_token","lease_owner","lease_until","next_boundary_at"))
                assertTrue(java.util.Objects.equals(before.get(column),pending.get(column)),"V46 changed preserved evidence: "+column);
            assertTrue(tuples.equals(ledger()),"V46 changed tuple intent");
        });
    }

    /** Proves a real MySQL transaction rolls back business, audit and outbox writes on completion expiry. */
    @Test
    void completionExpiryRollsBackBusinessAuditAndOutboxTogether() {
        Map<String,List<Map<String,Object>>> before=businessState();
        Map<String,Object> projection=state();
        List<Map<String,Object>> tuples=ledger();
        Instant now=Instant.now(),boundary=now.plusSeconds(60);
        java.util.concurrent.atomic.AtomicReference<Instant> time=new java.util.concurrent.atomic.AtomicReference<>(now);
        java.time.Clock clock=mock(java.time.Clock.class);
        when(clock.instant()).thenAnswer(call->time.get());
        UUID actor=UUID.fromString(required("AUTH_PHASE5_ACTOR_ACCOUNT_ID"));
        UUID group=UUID.fromString(required("AUTH_PHASE5_TEAM_ID"));
        com.unidocs.auth.session.domain.UserSession session=new com.unidocs.auth.session.domain.UserSession(
                UUID.randomUUID(),UUID.randomUUID(),actor,"ACTIVE",now,now,now.plusSeconds(3600),null);
        com.unidocs.auth.session.domain.SessionAccountGrant grant=new com.unidocs.auth.session.domain.SessionAccountGrant(
                session.id(),actor,"ACTIVE","LOGIN",1,boundary,now.plusSeconds(3600));
        com.unidocs.auth.session.persistence.SessionRepository sessions=mock(com.unidocs.auth.session.persistence.SessionRepository.class);
        when(sessions.liveGrant(session,actor,now)).thenReturn(java.util.Optional.of(grant));
        com.unidocs.auth.authorization.application.ProfessionalAuthorizationService authorization=
                new com.unidocs.auth.authorization.application.ProfessionalAuthorizationService(jdbc,sessions,
                        mock(com.unidocs.auth.organization.persistence.OrganizationRepository.class),
                        mock(com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository.class),clock);
        TransactionTemplate transaction=new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        try {
            assertThrows(com.unidocs.auth.authorization.application.OperationAuthorizationFailure.class,()->transaction.execute(status->{
                authorization.guardTransactionCompletion(new com.unidocs.auth.session.application.SessionAccess.Context(session,null,grant,now),actor,null);
                assertEquals(1,jdbc.update("UPDATE group_rule SET version=version+1 WHERE organization_id=? AND group_id=?",bytes(organization),bytes(group)));
                jdbc.update("INSERT INTO iam_professional_audit VALUES(?,?,?,?,?,?,?,?)",bytes(UUID.randomUUID()),bytes(organization),bytes(actor),
                        bytes(session.id()),null,"PHASE5_COMPLETION_TEST",1,java.sql.Timestamp.from(now));
                new OutboxRepository(jdbc).lifecycle("ORGANIZATION",organization,1,"PHASE5_COMPLETION_TEST",actor,organization,null,now);
                time.set(boundary);
                return true;
            }));
        } finally {
            assertTrue(before.equals(businessState()),"Completion failure left business/audit/outbox changes");
            assertTrue(projection.equals(state()),"Completion failure left projection changes");
            assertTrue(tuples.equals(ledger()),"Completion failure changed tuple intent");
        }
    }

    /**
     * Runs only uncommitted fixture variations and verifies all touched business/projection state is restored.
     * @param operation rollback-only scenario
     */
    private void rollbackVerified(Runnable operation) {
        Map<String,List<Map<String,Object>>> before=businessState();
        Map<String,Object> projection=state();
        List<Map<String,Object>> tuples=ledger();
        try {
            new TransactionTemplate(new DataSourceTransactionManager(dataSource)).executeWithoutResult(status->{
                status.setRollbackOnly();
                operation.run();
            });
        } finally {
            assertTrue(before.equals(businessState()),"Rollback changed existing fixture/catalog/audit/outbox state");
            assertTrue(projection.equals(state()),"Rollback changed projection evidence");
            assertTrue(tuples.equals(ledger()),"Rollback changed tuple intent");
        }
    }

    /** @return deterministic snapshots of tables touched by rollback-only scenarios, without credential columns */
    private Map<String,List<Map<String,Object>>> businessState() {
        Map<String,List<Map<String,Object>>> result=new java.util.LinkedHashMap<>();
        for(String table:List.of("iam_group","group_rule","group_membership","organization_membership","iam_professional_assignment","iam_professional_audit","outbox_event")) {
            String filter=table.equals("outbox_event")?"aggregate_id":"organization_id";
            String order=table.equals("group_rule")?"group_id":"id";
            result.put(table,normalized(jdbc.queryForList("SELECT * FROM "+table+" WHERE "+filter+"=? ORDER BY "+order,bytes(organization))));
        }
        result.put("accounts",normalized(jdbc.queryForList("SELECT id,type,status,organization_id FROM user_account WHERE organization_id=? ORDER BY id",bytes(organization))));
        result.put("roleAuthorities",normalized(jdbc.queryForList("SELECT * FROM iam_role_authority ORDER BY role_id,authority_id")));
        result.put("authorities",normalized(jdbc.queryForList("SELECT * FROM iam_authority ORDER BY id")));
        return result;
    }

    /** @param rows JDBC rows @return comparable row values with binary IDs normalized in memory */
    private List<Map<String,Object>> normalized(List<Map<String,Object>> rows) {
        return rows.stream().map(row->{
            Map<String,Object> normalized=new java.util.LinkedHashMap<>();
            row.forEach((key,value)->normalized.put(key,value instanceof byte[] binary?java.util.HexFormat.of().formatHex(binary):value));
            return normalized;
        }).toList();
    }

    /** @param now snapshot time @return desired tuples from the real source queries, without any remote writes */
    private java.util.Set<SpiceDbRelationship> projected(Instant now) {
        Object snapshot=org.springframework.test.util.ReflectionTestUtils.invokeMethod(sync,"loadOrganizationAuthorizationSnapshot",organization,now);
        return org.springframework.test.util.ReflectionTestUtils.invokeMethod(snapshot,"relationships");
    }

    /** @param key seeded role key @return existing responsibility role identity */
    private UUID role(String key) { return UUID.fromString(jdbc.queryForObject("SELECT BIN_TO_UUID(id) FROM iam_role WHERE role_key=? AND status='ACTIVE'",String.class,key)); }
    /** @param key seeded authority key @return existing active Auth authority identity */
    private UUID authority(String key) { return UUID.fromString(jdbc.queryForObject("SELECT BIN_TO_UUID(id) FROM iam_authority WHERE service_id='auth-service' AND authority_key=? AND status='ACTIVE'",String.class,key)); }
    /** @param id identity @return compact graph identity */
    private String compact(UUID id) { return id.toString().replace("-",""); }

    /** @param account existing fixture account @param group optional scope @param role existing role @param now test time */
    private void assignResponsibility(UUID account,UUID group,UUID role,Instant now) {
        byte[] membership=jdbc.queryForObject("SELECT id FROM organization_membership WHERE organization_id=? AND account_id=? AND status='ACTIVE'",byte[].class,bytes(organization),bytes(account));
        jdbc.update("""
                INSERT INTO iam_professional_assignment(id,organization_id,membership_id,account_id,group_id,role_id,status,valid_from,valid_until)
                VALUES(?,?,?,?,?,?,'ACTIVE',?,NULL) ON DUPLICATE KEY UPDATE status='ACTIVE',valid_from=VALUES(valid_from),valid_until=NULL
                """,bytes(UUID.randomUUID()),bytes(organization),membership,bytes(account),group==null?null:bytes(group),bytes(role),java.sql.Timestamp.from(now.minusSeconds(3600)));
    }

    /** @param account existing fixture account @param department existing department @param now test time */
    private void activateDepartmentMember(UUID account,UUID department,Instant now) {
        byte[] membership=jdbc.queryForObject("SELECT id FROM group_membership WHERE organization_id=? AND group_id=? AND account_id=? ORDER BY created_at DESC,id DESC LIMIT 1",
                byte[].class,bytes(organization),bytes(department),bytes(account));
        assertEquals(1,jdbc.update("UPDATE group_membership SET status='ACTIVE',membership_type='PERMANENT',valid_from=?,valid_until=NULL,revoked_at=NULL,revoked_by_account_id=NULL WHERE id=?",
                java.sql.Timestamp.from(now.minusSeconds(3600)),membership));
    }

    /**
     * Selects only the existing loopback test database and an explicitly supplied cohort.
     * @throws IllegalArgumentException when the test credentials or cohort are absent
     */
    @BeforeEach
    void connectToExistingSchema() {
        String port = System.getenv().getOrDefault("AUTH_PHASE5_MYSQL_PORT", "3306");
        if (!port.matches("[0-9]{1,5}") || Integer.parseInt(port) < 1 || Integer.parseInt(port) > 65535)
            throw new IllegalArgumentException("A valid existing MySQL loopback port is required");
        dataSource = new DriverManagerDataSource("jdbc:mysql://127.0.0.1:" + port
                + "/auth_service_test?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true"
                + "&connectTimeout=5000&socketTimeout=10000", required("AUTH_TEST_DB_USERNAME"),
                required("AUTH_TEST_DB_PASSWORD"));
        jdbc = new JdbcTemplate(dataSource);
        jdbc.setQueryTimeout(5);
        assertEquals("auth_service_test", jdbc.queryForObject("SELECT DATABASE()", String.class));
        organization = UUID.fromString(required("AUTH_PHASE5_ORGANIZATION_ID"));
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM spicedb_organization_sync_state "
                + "WHERE organization_id=? AND lease_owner IS NULL AND required_revision=applied_revision "
                + "AND required_source_version=applied_source_version AND sync_status='APPLIED'", Integer.class,
                bytes(organization)));
        SpiceDbOrganizationSyncProperties properties = new SpiceDbOrganizationSyncProperties(false,
                "spicedb-api-gateway:50051", "", true, 500, 1000, 1, 300, 5000);
        sync = new SpiceDbOrganizationSyncService(jdbc, new DataSourceTransactionManager(dataSource), properties);
    }

    /**
     * Exercises the real worker's advisory-lock exclusion without sending graph writes.
     * @throws Exception when the existing database or bounded worker task fails
     */
    @Test
    void competingWorkerCannotEnterWhileAnotherConnectionOwnsOrganizationLock() throws Exception {
        Map<String, Object> before = state();
        List<Map<String, Object>> ledger = ledger();
        SpiceDbRelationshipWriter writer = mock(SpiceDbRelationshipWriter.class);
        try (Connection connection = dataSource.getConnection()) {
            String lock = "spicedb-org-" + organization.toString().replace("-", "");
            assertEquals(1, advisoryLock(connection, "SELECT GET_LOCK(?, 0)", lock));
            try (java.util.concurrent.ExecutorService executor = Executors.newSingleThreadExecutor()) {
                executor.submit(() -> sync.synchronizeOrganization(organization, UUID.randomUUID(), writer,
                        Instant.now())).get(3, TimeUnit.SECONDS);
                verifyNoInteractions(writer);
            } finally {
                assertEquals(1, advisoryLock(connection, "SELECT RELEASE_LOCK(?)", lock));
            }
        }
        assertEquals(before, state());
        assertEquals(ledger, ledger());
    }

    /**
     * Ensures acknowledgement waits for the source transaction and cannot accept its rolled-back lease.
     * @throws Exception when the existing database or bounded acknowledgement task fails
     */
    @Test
    void acknowledgementWaitsForSourceLockThenRejectsRolledBackSource() throws Exception {
        Map<String, Object> before = state();
        List<Map<String, Object>> ledger = ledger();
        long revision = ((Number) before.get("required_revision")).longValue();
        long source = ((Number) before.get("required_source_version")).longValue();
        UUID lease = UUID.randomUUID();
        try (Connection connection = dataSource.getConnection();
                java.util.concurrent.ExecutorService executor = Executors.newSingleThreadExecutor()) {
            connection.setAutoCommit(false);
            try {
                // Only uncommitted projection bookkeeping changes; business data and graph tuples are untouched.
                try (PreparedStatement update = connection.prepareStatement("UPDATE spicedb_organization_sync_state "
                        + "SET required_source_version=?,lease_owner=?,lease_until=TIMESTAMPADD(SECOND,30,UTC_TIMESTAMP(6)) "
                        + "WHERE organization_id=?")) {
                    update.setLong(1, source + 1);
                    update.setBytes(2, bytes(lease));
                    update.setBytes(3, bytes(organization));
                    assertEquals(1, update.executeUpdate());
                }
                CountDownLatch started = new CountDownLatch(1);
                java.util.concurrent.Future<?> acknowledgement = executor.submit(() -> {
                    started.countDown();
                    sync.acknowledgeProjection(organization, lease, revision, source + 1, source + 1,
                            null, List.of(), "unacknowledged-test-token", Instant.now());
                });
                assertTrue(started.await(2, TimeUnit.SECONDS));
                assertThrows(TimeoutException.class, () -> acknowledgement.get(250, TimeUnit.MILLISECONDS));
                connection.rollback();
                acknowledgement.get(5, TimeUnit.SECONDS);
            } finally {
                connection.rollback();
            }
        }
        assertEquals(before, state());
        assertEquals(ledger, ledger());
    }

    /** Verifies monotonic notification fences and atomic rollback of their outbox and projection bookkeeping. */
    @Test
    void duplicateAndOutOfOrderNotificationsCannotLowerTheRequiredSourceFence() {
        Map<String, Object> before = state();
        List<Map<String, Object>> ledger = ledger();
        long revision = ((Number) before.get("required_revision")).longValue();
        long source = ((Number) before.get("required_source_version")).longValue();
        Long events = jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE aggregate_type='ORGANIZATION' "
                + "AND aggregate_id=?", Long.class, bytes(organization));
        TransactionTemplate transaction = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        transaction.executeWithoutResult(status -> {
            status.setRollbackOnly();
            OutboxRepository outbox = new OutboxRepository(jdbc);
            // Projection is reconstructed from current MySQL facts; notification order cannot supply older tuples.
            for (long version : new long[]{source + 1, source, source + 1}) {
                outbox.lifecycle("ORGANIZATION", organization, version, "PHASE5_FENCE_TEST", null,
                        organization, null, Instant.now());
                Map<String, Object> pending = state();
                assertEquals(source + 1, ((Number) pending.get("required_source_version")).longValue());
                assertEquals("PENDING", pending.get("sync_status"));
                assertEquals(before.get("applied_revision"), pending.get("applied_revision"));
                assertEquals(before.get("zed_token"), pending.get("zed_token"));
            }
            assertEquals(revision + 3, ((Number) state().get("required_revision")).longValue());
            assertEquals(events + 3, jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event "
                    + "WHERE aggregate_type='ORGANIZATION' AND aggregate_id=?", Long.class, bytes(organization)));
        });
        assertEquals(before, state());
        assertEquals(ledger, ledger());
        assertEquals(events, jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event "
                + "WHERE aggregate_type='ORGANIZATION' AND aggregate_id=?", Long.class, bytes(organization)));
    }

    /** @return projection state with binary fields normalized for exact before/after comparison */
    private Map<String, Object> state() {
        return jdbc.queryForMap("SELECT required_revision,applied_revision,required_source_version,applied_source_version,"
                + "sync_status,zed_token,next_boundary_at,HEX(lease_owner) lease_owner,lease_until,attempts,"
                + "available_at,last_error_code,created_at,updated_at FROM spicedb_organization_sync_state "
                + "WHERE organization_id=?", bytes(organization));
    }

    /** @return the complete existing cohort tuple ledger without changing its rows */
    private List<Map<String, Object>> ledger() {
        return jdbc.queryForList("SELECT HEX(tuple_hash) tuple_hash,resource_type,resource_id,relation_name,"
                + "subject_type,subject_id,created_at FROM spicedb_organization_sync_tuple "
                + "WHERE organization_id=? ORDER BY tuple_hash", bytes(organization));
    }

    /**
     * Executes one connection-owned advisory-lock operation.
     * @param connection lock owner connection
     * @param sql fixed GET_LOCK or RELEASE_LOCK statement
     * @param lock organization lock name
     * @return MySQL lock result
     * @throws java.sql.SQLException when the existing database cannot execute the lock statement
     */
    private int advisoryLock(Connection connection, String sql, String lock) throws java.sql.SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, lock);
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                return result.getInt(1);
            }
        }
    }

    /**
     * Reads explicit test configuration without including its value in errors.
     * @param name required environment variable
     * @return nonblank configuration value
     * @throws IllegalArgumentException when configuration is absent
     */
    private String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing " + name);
        return value;
    }
}
