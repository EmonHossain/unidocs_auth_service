package com.unidocs.auth.authorization.application;

import com.authzed.api.v1.CheckPermissionRequest;
import com.authzed.api.v1.CheckPermissionResponse;
import com.authzed.api.v1.Consistency;
import com.authzed.api.v1.ObjectReference;
import com.authzed.api.v1.SubjectReference;
import com.authzed.api.v1.ZedToken;
import com.unidocs.auth.authorization.api.OperationAuthorizationResponse;
import com.unidocs.auth.authorization.domain.AuthorityMatchMode;
import com.unidocs.auth.authorization.domain.OperationPolicySnapshot;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import com.unidocs.auth.security.spicedb.SpiceDbPermissionClient;
import com.unidocs.auth.session.application.SessionAccess;
import io.micrometer.core.instrument.MeterRegistry;
import io.grpc.StatusRuntimeException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Organization canary with fenced graph checks and current IAM revalidation. */
@Service
@ConditionalOnProperty(prefix = "auth.spicedb.canary", name = "enabled", havingValue = "true")
public final class ProfessionalSpiceDbCanary {
    private static final String GROUP_CREATE = "organization.group.create";
    private static final String EMPLOYEE_CREATE = "organization.employee.create";
    private static final String WORKSPACE_READ = "workspace.read";
    private static final Set<String> CONTENT_OPERATIONS = Set.of(
            "workspace.create", WORKSPACE_READ, "quota.read", "deletion.read", "organization.quota.read",
            "organization.deletion.policy.update", "file.read", "file.download", "file.create", "file.edit",
            "file.collaborative.edit", "file.copy", "file.move", "file.rename", "file.delete.schedule", "file.restore",
            "file.share", "file.share.view", "file.share.edit", "file.share.revoke", "content.access.update",
            "folder.read", "folder.create", "folder.rename", "folder.move", "folder.copy", "folder.delete.schedule",
            "folder.restore", "folder.share", "folder.share.view", "folder.share.edit", "folder.share.revoke",
            "publication.submit", "publication.approve", "publication.reject", "publication.read",
            "publication.edit.own", "publication.delete.schedule");
    private static final Set<String> MANAGEMENT_OPERATIONS = Set.of(GROUP_CREATE, EMPLOYEE_CREATE,
            "organization.employee.remove", "organization.employee.reset", "organization.responsibility.assign",
            "organization.access.update", "organization.department.assign", "organization.group.assign",
            "organization.group.unassign", "department.access.update", "team.access.update",
            "organization.collaboration.invite");
    private final Set<UUID> organizations;
    private final boolean employeeCreateEnabled;
    private final boolean managementEnabled;
    private final boolean enforcementEnabled;
    private final boolean workspaceReadEnabled;
    private final boolean contentEnabled;
    private final SessionAccess access;
    private final ProfessionalAuthorizationService professional;
    private final OperationPolicyCatalogRepository policies;
    private final SpiceDbPermissionClient spiceDb;
    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final MeterRegistry metrics;

    /**
     * Configures independent management and strict content selection within a bounded cohort.
     * @param organizationIds explicit organization cohort
     * @param employeeCreateEnabled whether employee creation is selected
     * @param managementEnabled whether all registered management operations are selected
     * @param enforcementEnabled whether selected management decisions replace SQL authority matching
     * @param workspaceReadEnabled whether workspace reads require the strict graph intersection
     * @param contentEnabled whether all registered content operations require the strict intersection
     * @param access current session transaction boundary
     * @param professional current professional SQL admission and authority checks
     * @param policies current operation policy catalog
     * @param spiceDb bounded permission client
     * @param jdbc owning Auth SQL access
     * @param clock current eligibility clock
     * @param metrics bounded decision metrics
     * @throws IllegalArgumentException when the cohort or enforcement configuration is invalid
     */
    @Autowired
    public ProfessionalSpiceDbCanary(@Value("${auth.spicedb.canary.organization-ids:}") String organizationIds,
            @Value("${auth.spicedb.canary.employee-create-enabled:false}") boolean employeeCreateEnabled,
            @Value("${auth.spicedb.canary.management-enabled:false}") boolean managementEnabled,
            @Value("${auth.spicedb.canary.enforcement-enabled:false}") boolean enforcementEnabled,
            @Value("${auth.spicedb.canary.workspace-read-enabled:false}") boolean workspaceReadEnabled,
            @Value("${auth.spicedb.canary.content-enabled:false}") boolean contentEnabled,
            SessionAccess access, ProfessionalAuthorizationService professional,
            OperationPolicyCatalogRepository policies, SpiceDbPermissionClient spiceDb, JdbcTemplate jdbc, Clock clock,
            MeterRegistry metrics) {
        this.organizations = Arrays.stream(organizationIds.split(",")).map(String::strip).filter(value -> !value.isEmpty())
                .map(UUID::fromString).collect(Collectors.toUnmodifiableSet());
        if (organizations.isEmpty() || organizations.size() > 20) {
            throw new IllegalArgumentException("SpiceDB canary requires a bounded explicit organization cohort.");
        }
        this.employeeCreateEnabled = employeeCreateEnabled;
        this.managementEnabled = managementEnabled;
        if(enforcementEnabled && !managementEnabled) {
            throw new IllegalArgumentException("Management enforcement requires the management cohort switch.");
        }
        this.enforcementEnabled = enforcementEnabled;
        this.workspaceReadEnabled = workspaceReadEnabled;
        this.contentEnabled = contentEnabled;
        this.access = access;
        this.professional = professional;
        this.policies = policies;
        this.spiceDb = spiceDb;
        this.jdbc = jdbc;
        this.clock = clock;
        this.metrics = metrics;
    }

    /**
     * Preserves management-only construction with content checks disabled.
     * @param organizationIds explicit organization cohort
     * @param employeeCreateEnabled employee-creation selection
     * @param managementEnabled management operation selection
     * @param enforcementEnabled management graph authority selection
     * @param access session transaction boundary
     * @param professional current professional SQL checks
     * @param policies current operation policy catalog
     * @param spiceDb bounded permission client
     * @param jdbc owning Auth SQL access
     * @param clock current eligibility clock
     * @param metrics bounded decision metrics
     */
    public ProfessionalSpiceDbCanary(String organizationIds, boolean employeeCreateEnabled, boolean managementEnabled,
            boolean enforcementEnabled, SessionAccess access, ProfessionalAuthorizationService professional,
            OperationPolicyCatalogRepository policies, SpiceDbPermissionClient spiceDb, JdbcTemplate jdbc, Clock clock,
            MeterRegistry metrics) {
        this(organizationIds, employeeCreateEnabled, managementEnabled, enforcementEnabled, false, false,
                access, professional, policies, spiceDb, jdbc, clock, metrics);
    }

    /**
     * Preserves workspace-only construction without selecting wider content checks.
     * @param organizationIds explicit organization cohort
     * @param employeeCreateEnabled employee-creation selection
     * @param managementEnabled management operation selection
     * @param enforcementEnabled management graph authority selection
     * @param workspaceReadEnabled workspace-read intersection selection
     * @param access session transaction boundary
     * @param professional current professional SQL checks
     * @param policies current operation policy catalog
     * @param spiceDb bounded permission client
     * @param jdbc owning Auth SQL access
     * @param clock current eligibility clock
     * @param metrics bounded decision metrics
     */
    public ProfessionalSpiceDbCanary(String organizationIds, boolean employeeCreateEnabled, boolean managementEnabled,
            boolean enforcementEnabled, boolean workspaceReadEnabled, SessionAccess access,
            ProfessionalAuthorizationService professional, OperationPolicyCatalogRepository policies,
            SpiceDbPermissionClient spiceDb, JdbcTemplate jdbc, Clock clock, MeterRegistry metrics) {
        this(organizationIds, employeeCreateEnabled, managementEnabled, enforcementEnabled, workspaceReadEnabled, false,
                access, professional, policies, spiceDb, jdbc, clock, metrics);
    }

    ProfessionalSpiceDbCanary(String organizationIds, SessionAccess access, ProfessionalAuthorizationService professional,
            OperationPolicyCatalogRepository policies, SpiceDbPermissionClient spiceDb, JdbcTemplate jdbc, Clock clock,
            MeterRegistry metrics) {
        this(organizationIds, false, false, false, access, professional, policies, spiceDb, jdbc, clock, metrics);
    }

    ProfessionalSpiceDbCanary(String organizationIds, boolean employeeCreateEnabled, boolean managementEnabled,
            SessionAccess access, ProfessionalAuthorizationService professional,
            OperationPolicyCatalogRepository policies, SpiceDbPermissionClient spiceDb, JdbcTemplate jdbc, Clock clock,
            MeterRegistry metrics) {
        this(organizationIds,employeeCreateEnabled,managementEnabled,false,access,professional,policies,spiceDb,jdbc,clock,metrics);
    }

    /**
     * Checks the configured organization cohort.
     * @param organization verified organization ID
     * @return true when this organization uses the strict canary
     */
    public boolean applies(UUID organization) {
        return organizations.contains(organization);
    }

    /**
     * Selects a registered canary operation in the server-owned organization cohort.
     * @param organization verified organization ID
     * @param operation registered operation key
     * @return whether the operation is selected
     */
    public boolean applies(UUID organization, String operation) {
        return applies(organization) && (managementEnabled && MANAGEMENT_OPERATIONS.contains(operation)
                || GROUP_CREATE.equals(operation)
                || employeeCreateEnabled && EMPLOYEE_CREATE.equals(operation)
                || workspaceReadEnabled && WORKSPACE_READ.equals(operation)
                || contentEnabled && CONTENT_OPERATIONS.contains(operation));
    }

    /**
     * Identifies a selected operation for which a SQL-only fallback is forbidden.
     * @param organization verified organization ID
     * @param operation registered operation key
     * @return whether the graph decision must accompany this operation
     */
    public boolean enforces(UUID organization, String operation) {
        // Content keeps the SQL intersection until Document resource parity and rollback gates pass.
        return enforcementEnabled && MANAGEMENT_OPERATIONS.contains(operation) && applies(organization, operation);
    }

    /**
     * Rejects a selected operation that reached its transactional entry point without graph evidence.
     * @param organization verified organization ID
     * @param group verified group scope, or null for organization scope
     * @param operation registered operation key
     * @param decision preflight decision, if selected
     * @throws OperationAuthorizationFailure when required graph evidence is absent or mismatched
     */
    public void requireDecision(UUID organization, UUID group, String operation, Decision decision) {
        if (applies(organization, operation) && (enforces(organization, operation) || CONTENT_OPERATIONS.contains(operation))
                && (decision == null || decision.enforcing() != enforces(organization, operation)
                || !organization.equals(decision.organization()) || !operation.equals(decision.operation())
                || !Objects.equals(group, decision.group()))) {
            throw unavailable();
        }
    }

    /**
     * Binds a content decision to the current request's separately verified resource admission mode.
     * @param organization verified owning organization
     * @param group verified owning group, or null
     * @param operation registered Document operation
     * @param exactResourceAccess current request's exact-resource admission hint
     * @param decision earlier content preflight evidence
     * @throws OperationAuthorizationFailure when selected evidence is absent or belongs to another admission mode
     */
    public void requireContentDecision(UUID organization, UUID group, String operation,
            boolean exactResourceAccess, Decision decision) {
        requireDecision(organization, group, operation, decision);
        if (applies(organization, operation) && CONTENT_OPERATIONS.contains(operation)
                && (decision == null || decision.exactResourceAccess() != exactResourceAccess)) throw unavailable();
    }

    /**
     * Checks group creation after a short IAM preflight transaction.
     * @param session authenticated session ID
     * @param subject authenticated login account ID
     * @param account selected account ID
     * @param organization verified organization ID
     * @return evidence to revalidate in the mutation transaction
     * @throws OperationAuthorizationFailure when authority is denied or unavailable
     */
    public Decision check(UUID session, UUID subject, UUID account, UUID organization) {
        return check(session, subject, account, organization, GROUP_CREATE);
    }

    /**
     * Checks one selected organization operation outside a SQL transaction.
     * @param session authenticated session ID
     * @param subject authenticated login account ID
     * @param account selected account ID
     * @param organization verified organization ID
     * @param operation registered operation key
     * @return evidence to revalidate in the mutation transaction
     * @throws OperationAuthorizationFailure when authority is denied or unavailable
     */
    public Decision check(UUID session, UUID subject, UUID account, UUID organization, String operation) {
        return check(session, subject, account, organization, null, operation);
    }

    /**
     * Checks a server-selected organization management operation and its verified group scope.
     * @param session authenticated session ID
     * @param subject authenticated login account ID
     * @param account selected account ID
     * @param organization verified organization ID
     * @param group verified group ID, or null for organization scope
     * @param operation registered operation key
     * @return evidence to revalidate in the mutation transaction
     * @throws OperationAuthorizationFailure when authority is denied or unavailable
     */
    public Decision check(UUID session, UUID subject, UUID account, UUID organization, UUID group, String operation) {
        return check(session, subject, account, organization, group, null, operation, false);
    }

    /**
     * Checks a registered Document operation without turning exact sharing into group membership.
     * @param session authenticated session ID
     * @param subject authenticated login account ID
     * @param account selected account ID
     * @param organization verified owning organization
     * @param group verified owning group, or null
     * @param operation server-registered content operation
     * @param exactResourceAccess separately verified Document relationship hint
     * @return graph and SQL intersection evidence bound to this admission mode
     * @throws OperationAuthorizationFailure when admission, authority or freshness fails
     */
    public Decision checkContent(UUID session, UUID subject, UUID account, UUID organization, UUID group,
            String operation, boolean exactResourceAccess) {
        if (!CONTENT_OPERATIONS.contains(operation)) throw denied();
        return check(session, subject, account, organization, group, null, operation, exactResourceAccess);
    }

    /**
     * Checks a group assignment against the recipient and one coherent management scope.
     * @param session authenticated session ID
     * @param subject authenticated login account ID
     * @param account selected account ID
     * @param organization verified organization ID
     * @param group target group ID
     * @param recipient target account ID
     * @param operation registered assignment operation
     * @return evidence to revalidate in the final transaction
     * @throws OperationAuthorizationFailure when authority or recipient eligibility is denied
     */
    public Decision checkAssignment(UUID session, UUID subject, UUID account, UUID organization, UUID group,
            UUID recipient, String operation) {
        if (group == null || recipient == null || !Set.of("organization.department.assign",
                "organization.group.assign", "organization.group.unassign").contains(operation)) throw denied();
        return check(session, subject, account, organization, group, recipient, operation, false);
    }

    private Decision check(UUID session, UUID subject, UUID account, UUID organization, UUID group,
            UUID recipient, String operation, boolean exactResourceAccess) {
        if (!applies(organization, operation) || TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("Canary checks require a selected organization and no active transaction.");
        }
        long started = System.nanoTime();
        String result = "allowed";
        try {
            boolean enforcing = enforces(organization, operation);
            String service = operationService(operation);
            Prepared prepared = access.execute(session, subject, context -> {
                OperationAuthorizationResponse response = enforcing
                        ? professional.previewGraph(context, account, organization, group,service,operation)
                        : professional.preview(context, account, organization, group,service,operation,exactResourceAccess);
                OperationPolicySnapshot policy = policies.findCurrent(service, operation, "ORGANIZATION")
                        .orElseThrow(ProfessionalSpiceDbCanary::denied);
                if (!samePolicy(response, policy)) throw denied();
                Set<UUID> ancestry = group == null ? Set.of() : professional.ancestors(organization, group);
                UUID recipientMembership = recipient == null ? null : recipientMembership(organization, recipient);
                UUID actorMembership = recipient == null ? null : recipientMembership(organization, account);
                Set<UUID> departments = group == null ? Set.of() : departments(organization, ancestry);
                return new Prepared(response, policy, fence(organization), scopeType(organization, group), ancestry,
                        departments, recipientMembership, actorMembership);
            });
            GraphEvidence graph = checkGraphEvidence(account, organization, group, prepared.scopeType(),
                    prepared.ancestry(), prepared.policy());
            RecipientScopeProof recipientScope = recipient == null ? null : recipientGraphScope(account, recipient,
                    organization, prepared.departments(), prepared.policy(), graph.authorities(), graph.snapshot(),
                    prepared.actorMembership());
            return new Decision(prepared.response(), prepared.fence(), organization, operation, group, prepared.scopeType(),
                    graph.authorities(),enforcing,recipient,prepared.recipientMembership(),
                    prepared.ancestry(),prepared.departments(),graph.snapshot().getToken(),recipientScope,exactResourceAccess);
        } catch (OperationAuthorizationFailure failure) {
            result = failure.status() == HttpStatus.SERVICE_UNAVAILABLE ? "unavailable" : "denied";
            throw failure;
        } catch (DataAccessException dependency) {
            result = "unavailable";
            throw unavailable();
        } catch (RuntimeException failure) {
            result = "error";
            throw failure;
        } finally {
            metrics.timer("auth.spicedb.canary.check.duration", "operation", operation, "result", result)
                    .record(System.nanoTime() - started, TimeUnit.NANOSECONDS);
        }
    }

    /**
     * Rejects graph evidence when IAM state or projection fences changed before mutation.
     * @param decision earlier graph decision
     * @param context current locked session context
     * @param account selected account ID
     * @param organization verified organization ID
     * @return current operation evidence after final IAM and graph-fence validation
     * @throws OperationAuthorizationFailure when authority changed or became unavailable
     */
    public OperationAuthorizationResponse revalidate(Decision decision, SessionAccess.Context context, UUID account, UUID organization) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("Canary revalidation requires the mutation transaction.");
        }
        try {
            if (decision == null || !applies(organization, decision.operation())
                    || !organization.equals(decision.organization())
                    || decision.enforcing() != enforces(organization, decision.operation()))
                throw unavailable();
            String service = operationService(decision.operation());
            OperationAuthorizationResponse current = decision.enforcing()
                    ? professional.requireGraph(context,account,organization,decision.group(),service,
                            decision.operation(),decision.graphAuthorities())
                    : professional.require(context, account, organization, decision.group(),service,decision.operation(),
                            decision.exactResourceAccess());
            if (!sameEvidence(decision.response(), current, decision.enforcing()) || !decision.fence().equals(fence(organization))
                    || !decision.scopeType().equals(scopeType(organization, decision.group()))) {
                throw unavailable();
            }
            if (decision.group() != null && (!decision.ancestry().equals(professional.ancestors(organization, decision.group()))
                    || !decision.departments().equals(departments(organization, decision.ancestry())))) throw unavailable();
            if (decision.recipient() != null && !decision.recipientMembership().equals(
                    recipientMembership(organization, decision.recipient()))) throw unavailable();
            if (decision.recipient() != null) revalidateRecipientScope(decision, account, organization);
            professional.revalidateGrant(context, account);
            // Scope locks can wait past a scheduled revocation even though the projection has not changed.
            Instant checkedAt = clock.instant();
            if (checkedAt.isBefore(current.checkedAt()) || decision.fence().nextBoundary() != null
                    && !checkedAt.isBefore(decision.fence().nextBoundary())) throw unavailable();
            professional.guardTransactionCompletion(context, account, decision.fence().nextBoundary());
            return CONTENT_OPERATIONS.contains(decision.operation())
                    ? contentIntersection(current, decision.graphAuthorities()) : current;
        } catch (DataAccessException dependency) {
            throw unavailable();
        }
    }

    /**
     * Binds assignment evidence to the recipient selected by the current command.
     * @param decision selected graph evidence, or null outside the cohort
     * @param recipient actual command recipient
     * @throws OperationAuthorizationFailure when evidence belongs to another recipient
     */
    public void requireAssignmentRecipient(Decision decision, UUID recipient) {
        if (decision != null && (!Objects.equals(recipient, decision.recipient()) || decision.recipientScope() == null))
            throw unavailable();
    }

    /**
     * Rechecks the exact scope that supplied the graph's same-authority recipient proof.
     * @param decision pinned graph evidence
     * @param account selected administrator account
     * @param organization verified organization
     * @throws OperationAuthorizationFailure when current membership or scope no longer matches
     */
    private void revalidateRecipientScope(Decision decision, UUID account, UUID organization) {
        RecipientScopeProof proof = decision.recipientScope();
        if (proof == null || proof.scope() == null || proof.actorMembership() == null || proof.authorities().isEmpty()
                || !decision.graphAuthorities().containsAll(proof.authorities())
                || !proof.actorMembership().equals(recipientMembership(organization, account))) throw unavailable();
        if (organization.equals(proof.scope())) return;
        if (!decision.departments().contains(proof.scope()) || !"department".equals(scopeType(organization, proof.scope())))
            throw unavailable();
        requireDepartmentMember(organization, proof.scope(), account, proof.actorMembership());
        requireDepartmentMember(organization, proof.scope(), decision.recipient(), decision.recipientMembership());
    }

    /**
     * Locks a current department membership anchored to the same organization membership used at preflight.
     * @param organization verified tenant
     * @param department graph-proved management scope
     * @param account actor or recipient account
     * @param membership preflight organization-membership identity
     * @throws OperationAuthorizationFailure when membership is absent, revoked or expired
     */
    private void requireDepartmentMember(UUID organization, UUID department, UUID account, UUID membership) {
        Instant now = clock.instant();
        List<UUID> members = jdbc.query("""
                SELECT gm.id FROM group_membership gm JOIN organization_membership om
                ON om.id=gm.organization_membership_id AND om.organization_id=gm.organization_id
                AND om.account_id=gm.account_id AND om.status='ACTIVE'
                WHERE gm.organization_id=? AND gm.group_id=? AND gm.account_id=? AND om.id=?
                AND gm.status='ACTIVE' AND gm.valid_from<=? AND (gm.valid_until IS NULL OR gm.valid_until>?) FOR SHARE
                """, (row, index) -> uuid(row.getBytes(1)), bytes(organization), bytes(department), bytes(account),
                bytes(membership), Timestamp.from(now), Timestamp.from(now));
        if (members.size() != 1) throw denied();
    }

    /**
     * Resolves the graph scope using the existing professional department versus local-group contract.
     * @param organization verified tenant
     * @param group current group, or null for organization scope
     * @return organization, department or team graph type
     * @throws OperationAuthorizationFailure when the current scope is missing or unsupported
     */
    private String scopeType(UUID organization, UUID group) {
        if (group == null) return "organization";
        List<String> types = jdbc.query("SELECT type FROM iam_group WHERE organization_id=? AND id=? AND status='ACTIVE' AND workspace_context='ORGANIZATION' FOR SHARE",
                (row, index) -> row.getString(1), bytes(organization), bytes(group));
        if (types.size() != 1) throw denied();
        return switch (types.getFirst()) {
            case "DEPARTMENT" -> "department";
            case "TEAM", "PROJECT", "CUSTOM" -> "team";
            default -> throw denied();
        };
    }

    private Fence fence(UUID organization) {
        List<Fence> rows = jdbc.query("""
                SELECT s.required_revision,s.applied_revision,s.required_source_version,s.applied_source_version,
                       s.sync_status,s.zed_token,s.next_boundary_at,o.authorization_version
                FROM spicedb_organization_sync_state s JOIN organization o ON o.id=s.organization_id
                WHERE s.organization_id=? FOR SHARE
                """, (row, index) -> {
            long required = row.getLong(1);
            long applied = row.getLong(2);
            long source = row.getLong(3);
            long appliedSource = row.getLong(4);
            String status = row.getString(5);
            String token = row.getString(6);
            Timestamp boundary = row.getTimestamp(7);
            long organizationVersion = row.getLong(8);
            if (required != applied || source != appliedSource || source != organizationVersion
                    || !"APPLIED".equals(status) || token == null || token.isBlank()
                    || boundary != null && !clock.instant().isBefore(boundary.toInstant())) throw unavailable();
            return new Fence(required, source, token, boundary == null ? null : boundary.toInstant());
        }, bytes(organization));
        if (rows.size() != 1) throw unavailable();
        return rows.getFirst();
    }

    Set<UUID> checkGraph(UUID account, UUID organization, OperationPolicySnapshot policy) {
        return checkGraph(account, organization, null, "organization", policy);
    }

    Set<UUID> checkGraph(UUID account, UUID organization, UUID group, String scopeType, OperationPolicySnapshot policy) {
        Set<UUID> ancestry = group == null ? Set.of() : Set.of(group);
        return checkGraphEvidence(account, organization, group, scopeType, ancestry, policy).authorities();
    }

    private GraphEvidence checkGraphEvidence(UUID account, UUID organization, UUID group, String scopeType,
            Set<UUID> ancestry, OperationPolicySnapshot policy) {
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("SpiceDB RPC cannot run inside a SQL transaction.");
        }
        try {
            CheckPermissionResponse membership = spiceDb.checkPermission(request("organization", organization.toString(),
                    "member", "account", account.toString(), null));
            ZedToken snapshot = membership.getCheckedAt();
            if (snapshot.getToken().isBlank()) throw unavailable();
            if (!allowed(membership)) throw denied();
            if (pinnedAllowed(spiceDb.checkPermission(request("organization", organization.toString(), "explicit_deny",
                    "operation", policy.operationId().toString(), snapshot)), snapshot)
                    || accountDenied(organization, policy.operationId(), account, snapshot)) throw denied();
            if (group != null && pinnedAllowed(spiceDb.checkPermission(request(scopeType, group.toString(), "explicit_deny",
                    "operation", policy.operationId().toString(), snapshot)), snapshot)) throw denied();
            for (UUID ancestor : ancestry) {
                if (accountDenied(ancestor, policy.operationId(), account, snapshot)) throw denied();
            }
            Set<UUID> matched = new HashSet<>();
            for (UUID authority : policy.policy().requiredAuthorityIds().stream().sorted().toList()) {
                if (!policy.categoryAuthorityIds().contains(authority)) {
                    if (policy.policy().matchMode() == AuthorityMatchMode.ALL_OF) throw denied();
                    continue;
                }
                String capability = compact(group == null ? organization : group) + compact(authority);
                boolean category = pinnedAllowed(spiceDb.checkPermission(request("scope_capability", capability,
                        "category_grant", "account", account.toString(), snapshot)), snapshot);
                boolean scoped = pinnedAllowed(spiceDb.checkPermission(request("scope_capability", capability,
                        "scoped_grant", "account", account.toString(), snapshot)), snapshot);
                if (category && scoped) matched.add(authority);
                else if (policy.policy().matchMode() == AuthorityMatchMode.ALL_OF) throw denied();
            }
            if (matched.isEmpty()) throw denied();
            return new GraphEvidence(Set.copyOf(matched), snapshot);
        } catch (StatusRuntimeException dependency) {
            metrics.counter("auth.spicedb.canary.dependency.failure", "stage", "authority",
                    "code", dependency.getStatus().getCode().name()).increment();
            throw unavailable();
        }
    }

    private boolean accountDenied(UUID scope, UUID operation, UUID account, ZedToken snapshot) {
        return pinnedAllowed(spiceDb.checkPermission(request("scope_operation", compact(scope) + compact(operation),
                "denied", "account", account.toString(), snapshot)), snapshot);
    }

    /**
     * Requires a same-authority recipient proof at the operation's pinned graph revision.
     * @param account selected actor
     * @param recipient selected recipient
     * @param organization verified tenant
     * @param departments verified ancestor departments
     * @param policy registered operation policy
     * @param authorities bounded target-operation witnesses
     * @param snapshot pinned graph revision
     * @throws OperationAuthorizationFailure when no eligible scope matches or the graph is unavailable
     */
    void checkRecipientGraph(UUID account, UUID recipient, UUID organization, Set<UUID> departments,
            OperationPolicySnapshot policy, Set<UUID> authorities, ZedToken snapshot) {
        recipientGraphScope(account, recipient, organization, departments, policy, authorities, snapshot, null);
    }

    /**
     * Records the precise managed scope and authority witnesses from the operation's graph revision.
     * @param account selected actor
     * @param recipient selected recipient
     * @param organization verified tenant
     * @param departments verified ancestor departments
     * @param policy current operation policy
     * @param authorities authorities proved for the target operation
     * @param snapshot pinned graph revision
     * @param actorMembership current actor organization-membership identity
     * @return one same-scope proof without combining unrelated branches
     * @throws OperationAuthorizationFailure when no eligible scope matches or the graph is unavailable
     */
    private RecipientScopeProof recipientGraphScope(UUID account, UUID recipient, UUID organization, Set<UUID> departments,
            OperationPolicySnapshot policy, Set<UUID> authorities, ZedToken snapshot, UUID actorMembership) {
        if (TransactionSynchronizationManager.isActualTransactionActive())
            throw new IllegalStateException("Recipient graph checks require no active SQL transaction.");
        try {
            if (!pinnedAllowed(spiceDb.checkPermission(request("organization", organization.toString(), "member",
                    "account", recipient.toString(), snapshot)), snapshot)) throw denied();
            Set<UUID> matched = scopeAuthorities(account, organization, authorities, snapshot);
            if (scopeMatches(matched, policy)) return new RecipientScopeProof(organization, matched, actorMembership);
            for (UUID ancestor : departments.stream().sorted().toList()) {
                if (!pinnedAllowed(spiceDb.checkPermission(request("department", ancestor.toString(), "member",
                        "account", account.toString(), snapshot)), snapshot)
                        || !pinnedAllowed(spiceDb.checkPermission(request("department", ancestor.toString(), "member",
                        "account", recipient.toString(), snapshot)), snapshot)) continue;
                matched = scopeAuthorities(account, ancestor, authorities, snapshot);
                if (scopeMatches(matched, policy)) return new RecipientScopeProof(ancestor, matched, actorMembership);
            }
            throw denied();
        } catch (StatusRuntimeException dependency) {
            metrics.counter("auth.spicedb.canary.dependency.failure", "stage", "recipient",
                    "code", dependency.getStatus().getCode().name()).increment();
            throw unavailable();
        }
    }

    /**
     * Intersects the category ceiling with direct professional responsibility at one managed scope and revision.
     * @param account selected actor
     * @param scope organization or ancestor department
     * @param authorities bounded operation witnesses
     * @param snapshot pinned graph revision
     * @return matching authority UUIDs for this scope only
     */
    private Set<UUID> scopeAuthorities(UUID account, UUID scope, Set<UUID> authorities, ZedToken snapshot) {
        Set<UUID> matched = new HashSet<>();
        for (UUID authority : authorities.stream().sorted().toList()) {
            String capability = compact(scope) + compact(authority);
            if (pinnedAllowed(spiceDb.checkPermission(request("scope_capability", capability, "category_grant",
                    "account", account.toString(), snapshot)), snapshot)
                    && pinnedAllowed(spiceDb.checkPermission(request("scope_capability", capability, "responsibility_grant",
                    "account", account.toString(), snapshot)), snapshot)) matched.add(authority);
        }
        return Set.copyOf(matched);
    }

    /**
     * Applies the registered authority match mode to a single scope's witnesses.
     * @param matched same-scope authority intersection
     * @param policy current registered policy
     * @return whether this scope satisfies the policy
     */
    private boolean scopeMatches(Set<UUID> matched, OperationPolicySnapshot policy) {
        return policy.policy().matchMode() == AuthorityMatchMode.ALL_OF
                ? matched.containsAll(policy.policy().requiredAuthorityIds()) : !matched.isEmpty();
    }

    private UUID recipientMembership(UUID organization, UUID account) {
        List<UUID> memberships = jdbc.query("""
                SELECT m.id FROM organization_membership m JOIN user_account a
                ON a.id=m.account_id AND a.status='ACTIVE' AND a.organization_id=m.organization_id
                JOIN users u ON u.id=a.user_id AND u.status='ACTIVE'
                JOIN organization o ON o.id=m.organization_id AND o.status='ACTIVE' AND o.type=a.type
                WHERE m.organization_id=? AND m.account_id=? AND m.status='ACTIVE'
                AND a.type IN('COMPANY','CUSTOM')
                AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r
                    WHERE r.organization_id=m.organization_id AND r.user_id=a.user_id
                    AND r.status IN('REMOVED','BLACKLISTED','PURGED')) FOR SHARE
                """, (row, index) -> uuid(row.getBytes(1)), bytes(organization), bytes(account));
        if (memberships.size() != 1) throw denied();
        return memberships.getFirst();
    }

    private Set<UUID> departments(UUID organization, Set<UUID> ancestry) {
        Set<UUID> departments = new HashSet<>();
        for (UUID ancestor : ancestry) {
            if ("department".equals(scopeType(organization, ancestor))) departments.add(ancestor);
        }
        return Set.copyOf(departments);
    }

    private static CheckPermissionRequest request(String resourceType, String resourceId, String permission,
            String subjectType, String subjectId, ZedToken snapshot) {
        Consistency consistency = snapshot == null ? Consistency.newBuilder().setFullyConsistent(true).build()
                : Consistency.newBuilder().setAtExactSnapshot(snapshot).build();
        return CheckPermissionRequest.newBuilder().setConsistency(consistency)
                .setResource(ObjectReference.newBuilder().setObjectType(resourceType).setObjectId(resourceId))
                .setPermission(permission).setSubject(SubjectReference.newBuilder().setObject(
                        ObjectReference.newBuilder().setObjectType(subjectType).setObjectId(subjectId))).build();
    }

    private static boolean allowed(CheckPermissionResponse response) {
        return switch (response.getPermissionship()) {
            case PERMISSIONSHIP_HAS_PERMISSION -> true;
            case PERMISSIONSHIP_NO_PERMISSION -> false;
            default -> throw unavailable();
        };
    }

    private static boolean pinnedAllowed(CheckPermissionResponse response, ZedToken snapshot) {
        if (!response.hasCheckedAt() || !snapshot.getToken().equals(response.getCheckedAt().getToken())) throw unavailable();
        return allowed(response);
    }

    private static boolean samePolicy(OperationAuthorizationResponse response, OperationPolicySnapshot policy) {
        return response.operationId().equals(policy.operationId()) && response.policyId().equals(policy.policyId())
                && response.operationVersion() == policy.operationVersion() && response.policyVersion() == policy.policyVersion()
                && response.categoryBindingVersion() == policy.categoryBindingVersion()
                && response.categoryRoleVersion() == policy.categoryRoleVersion()
                && response.authorityVersions().equals(policy.authorityVersions());
    }

    private static boolean sameEvidence(OperationAuthorizationResponse before, OperationAuthorizationResponse after,
            boolean graphAuthoritative) {
        return before.accountId().equals(after.accountId()) && before.userId().equals(after.userId())
                && before.sessionId().equals(after.sessionId()) && before.operationId().equals(after.operationId())
                && before.policyId().equals(after.policyId()) && before.matchMode() == after.matchMode()
                && before.requiredAuthorities().equals(after.requiredAuthorities())
                && (graphAuthoritative || before.categoryAuthorities().equals(after.categoryAuthorities()))
                && before.operationVersion() == after.operationVersion() && before.policyVersion() == after.policyVersion()
                && before.categoryBindingVersion() == after.categoryBindingVersion()
                && before.categoryRoleVersion() == after.categoryRoleVersion()
                && before.catalogVersion() == after.catalogVersion()
                && before.authorityVersions().equals(after.authorityVersions());
    }

    private static String compact(UUID id) {
        return id.toString().replace("-", "");
    }

    /**
     * Resolves the service from the bounded server-owned operation selection.
     * @param operation selected operation key
     * @return the owning service identifier
     */
    private static String operationService(String operation) {
        return CONTENT_OPERATIONS.contains(operation) ? "document-service" : "auth-service";
    }

    /**
     * Exposes only identical SQL and pinned graph witnesses for Document's resource-layer intersection.
     * @param response current SQL admission and authority evidence
     * @param graphAuthorities exact authority UUIDs established at the pinned graph snapshot
     * @return immediate-expiry evidence with the common authority keys
     * @throws OperationAuthorizationFailure when no complete current-policy intersection exists
     */
    private OperationAuthorizationResponse contentIntersection(OperationAuthorizationResponse response,
            Set<UUID> graphAuthorities) {
        Set<String> matched = new HashSet<>();
        jdbc.query("""
                SELECT a.id,a.authority_key FROM iam_policy_authority p
                JOIN iam_authority a ON a.id=p.authority_id AND a.status='ACTIVE' WHERE p.policy_id=?
                """, row -> {
            if (graphAuthorities.contains(uuid(row.getBytes(1)))
                    && response.categoryAuthorities().contains(row.getString(2))) matched.add(row.getString(2));
        }, bytes(response.policyId()));
        if (matched.isEmpty() || response.matchMode() == AuthorityMatchMode.ALL_OF
                && !matched.containsAll(response.requiredAuthorities())) throw denied();
        return new OperationAuthorizationResponse(response.accountId(), response.userId(), response.sessionId(),
                response.operationId(), response.operationKey(), response.categoryKey(), response.policyId(),
                response.matchMode(), response.requiredAuthorities(), matched, response.operationVersion(),
                response.policyVersion(), response.categoryBindingVersion(), response.categoryRoleVersion(),
                response.catalogVersion(), response.authorityVersions(), response.checkedAt(), response.validUntil(),
                response.reasonCode());
    }

    private static UUID uuid(byte[] value) {
        java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(value);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    private static OperationAuthorizationFailure denied() {
        return new OperationAuthorizationFailure(HttpStatus.FORBIDDEN, "PROFESSIONAL_AUTHORITY_DENIED");
    }

    private static OperationAuthorizationFailure unavailable() {
        return new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE, "SPICEDB_AUTHORIZATION_UNAVAILABLE");
    }

    public record Decision(OperationAuthorizationResponse response, Fence fence, UUID organization, String operation, UUID group,
            String scopeType, Set<UUID> graphAuthorities, boolean enforcing, UUID recipient, UUID recipientMembership,
            Set<UUID> ancestry, Set<UUID> departments, String graphSnapshotToken, RecipientScopeProof recipientScope,
            boolean exactResourceAccess) {
        /** Copies mutable caller collections so graph evidence cannot change after preflight. */
        public Decision {
            graphAuthorities = Set.copyOf(graphAuthorities);
            ancestry = Set.copyOf(ancestry);
            departments = Set.copyOf(departments);
        }

        /**
         * Preserves management evidence without Document exact-resource admission.
         * @param response preflight IAM evidence
         * @param fence projection revision
         * @param organization selected organization
         * @param operation registered operation
         * @param group selected group
         * @param scopeType selected graph scope type
         * @param graphAuthorities graph authority intersection
         * @param enforcing whether management graph authority is selected
         * @param recipient optional assignment recipient
         * @param recipientMembership optional recipient membership
         * @param ancestry verified owning ancestry
         * @param departments verified departments
         * @param graphSnapshotToken pinned graph revision
         * @param recipientScope optional same-scope recipient proof
         */
        public Decision(OperationAuthorizationResponse response, Fence fence, UUID organization, String operation, UUID group,
                String scopeType, Set<UUID> graphAuthorities, boolean enforcing, UUID recipient, UUID recipientMembership,
                Set<UUID> ancestry, Set<UUID> departments, String graphSnapshotToken, RecipientScopeProof recipientScope) {
            this(response, fence, organization, operation, group, scopeType, graphAuthorities, enforcing, recipient,
                    recipientMembership, ancestry, departments, graphSnapshotToken, recipientScope, false);
        }

        /**
         * Preserves construction of non-assignment evidence; recipient evidence needs an explicit scope proof.
         * @param response preflight IAM evidence
         * @param fence projection revision
         * @param organization selected organization
         * @param operation registered operation
         * @param group selected group
         * @param scopeType selected scope type
         * @param graphAuthorities graph authority intersection
         * @param enforcing whether graph authority is selected
         * @param recipient optional assignment recipient
         * @param recipientMembership optional recipient membership
         * @param ancestry verified owning ancestry
         * @param departments verified departments
         * @param graphSnapshotToken pinned revision
         */
        public Decision(OperationAuthorizationResponse response, Fence fence, UUID organization, String operation, UUID group,
                String scopeType, Set<UUID> graphAuthorities, boolean enforcing, UUID recipient, UUID recipientMembership,
                Set<UUID> ancestry, Set<UUID> departments, String graphSnapshotToken) {
            this(response, fence, organization, operation, group, scopeType, graphAuthorities, enforcing, recipient,
                    recipientMembership, ancestry, departments, graphSnapshotToken, null);
        }
    }
    public record RecipientScopeProof(UUID scope, Set<UUID> authorities, UUID actorMembership) {
        /** Keeps the same-scope witness set immutable after the external graph read. */
        public RecipientScopeProof { authorities = Set.copyOf(authorities); }
    }
    public record Fence(long requiredRevision, long sourceVersion, String zedToken, Instant nextBoundary) { }
    private record Prepared(OperationAuthorizationResponse response, OperationPolicySnapshot policy, Fence fence,
            String scopeType, Set<UUID> ancestry, Set<UUID> departments, UUID recipientMembership, UUID actorMembership) { }
    private record GraphEvidence(Set<UUID> authorities, ZedToken snapshot) { }
}
