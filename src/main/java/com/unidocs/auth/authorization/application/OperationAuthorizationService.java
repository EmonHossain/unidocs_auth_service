package com.unidocs.auth.authorization.application;

import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.authorization.api.*;
import com.unidocs.auth.authorization.domain.*;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.persistence.SessionRepository;
import com.unidocs.auth.security.spicedb.IndividualSpiceDbGuard;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Service
@Transactional(propagation = Propagation.NEVER)
public class OperationAuthorizationService {
    private final JwtDecoder users;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final OperationRegistry registry;
    private final OperationPolicyCatalogRepository policies;
    private final OperationPolicyCandidateCache candidates;
    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final MeterRegistry metrics;
    private final com.unidocs.auth.group.personal.PersonalGroupAccess personalGroups;
    private final ProfessionalAuthorizationService professional;
    private final com.unidocs.auth.student.StudentAuthorization students;
    private final ProfessionalSpiceDbCanary canary;
    private IndividualSpiceDbGuard individual;

    @Autowired
    public OperationAuthorizationService(@Qualifier("jwtDecoder") JwtDecoder users, SessionAccess access,
            SessionRepository sessions, OperationRegistry registry, OperationPolicyCatalogRepository policies,
            OperationPolicyCandidateCache candidates, JdbcTemplate jdbc, Clock clock, MeterRegistry metrics,
            com.unidocs.auth.group.personal.PersonalGroupAccess personalGroups, ProfessionalAuthorizationService professional,
            com.unidocs.auth.student.StudentAuthorization students,ObjectProvider<ProfessionalSpiceDbCanary> canaryProvider,
            IndividualSpiceDbGuard individual) {
        this(users,access,sessions,registry,policies,candidates,jdbc,clock,metrics,personalGroups,professional,students,
                canaryProvider.getIfAvailable());
        this.individual = individual;
    }
    /** Preserves explicit construction with the existing professional canary provider. */
    public OperationAuthorizationService(JwtDecoder users, SessionAccess access,
            SessionRepository sessions, OperationRegistry registry, OperationPolicyCatalogRepository policies,
            OperationPolicyCandidateCache candidates, JdbcTemplate jdbc, Clock clock, MeterRegistry metrics,
            com.unidocs.auth.group.personal.PersonalGroupAccess personalGroups, ProfessionalAuthorizationService professional,
            com.unidocs.auth.student.StudentAuthorization students, ObjectProvider<ProfessionalSpiceDbCanary> canaryProvider) {
        this(users, access, sessions, registry, policies, candidates, jdbc, clock, metrics, personalGroups, professional,
                students, canaryProvider.getIfAvailable());
    }
    public OperationAuthorizationService(@Qualifier("jwtDecoder") JwtDecoder users, SessionAccess access,
            SessionRepository sessions, OperationRegistry registry, OperationPolicyCatalogRepository policies,
            OperationPolicyCandidateCache candidates, JdbcTemplate jdbc, Clock clock, MeterRegistry metrics,
            com.unidocs.auth.group.personal.PersonalGroupAccess personalGroups, ProfessionalAuthorizationService professional,
            com.unidocs.auth.student.StudentAuthorization students) {
        this(users,access,sessions,registry,policies,candidates,jdbc,clock,metrics,personalGroups,professional,students,
                (ProfessionalSpiceDbCanary)null);
    }
    private OperationAuthorizationService(JwtDecoder users, SessionAccess access,
            SessionRepository sessions, OperationRegistry registry, OperationPolicyCatalogRepository policies,
            OperationPolicyCandidateCache candidates, JdbcTemplate jdbc, Clock clock, MeterRegistry metrics,
            com.unidocs.auth.group.personal.PersonalGroupAccess personalGroups, ProfessionalAuthorizationService professional,
            com.unidocs.auth.student.StudentAuthorization students,ProfessionalSpiceDbCanary canary) {
        this.users = users; this.access = access; this.sessions = sessions; this.registry = registry;
        this.policies = policies; this.candidates = candidates; this.jdbc = jdbc; this.clock = clock; this.metrics = metrics;
        this.personalGroups = personalGroups;
        this.professional = professional;
        this.students = students;
        this.canary = canary;
    }

    @PreAuthorize("hasAuthority('SCOPE_iam.authorization.read')")
    public OperationAuthorizationResponse evaluate(Authentication service, String delegated, OperationAuthorizationRequest request) {
        requireDocumentService(service);
        // Document may request only this IAM-owned collaboration capability, never arbitrary IAM mutations.
        String operationService=Set.of("organization.collaboration.invite","group.invitation.accept").contains(request.operationKey())?"auth-service":"document-service";
        registry.require(operationService, request.operationKey(), request.resourceKind());
        if(request.operationKey().equals("organization.collaboration.invite") && (request.organizationId()==null || request.groupId()==null)) throw denied("PROFESSIONAL_GROUP_REQUIRED");
        if(request.exactResourceAccess() && (!Set.of("FILE","FOLDER").contains(request.resourceKind())
                || !Set.of("file.read","file.download","file.copy","file.edit","file.collaborative.edit","folder.read","folder.copy").contains(request.operationKey()))) {
            throw denied("RESOURCE_RELATIONSHIP_NOT_SUPPORTED");
        }
        UUID institution=students.institution(request.accountId());
        if(request.operationKey().equals("group.invitation.accept")&&institution==null) throw denied("STUDENT_CONTEXT_REQUIRED");
        if(institution!=null) {
            if(request.organizationId()!=null&&!institution.equals(request.organizationId())) throw denied("INSTITUTION_MISMATCH");
            return execute(delegated,context->{
                requireDocumentService(service);
                OperationAuthorizationResponse result=students.require(context,request.accountId(),institution,request.groupId(),operationService,request.operationKey());
                requireDocumentService(service);return result;
            });
        }
        if (request.organizationId() != null) {
            ProfessionalSpiceDbCanary.Decision decision=null;
            if(canary!=null && canary.applies(request.organizationId(),request.operationKey())) {
                Jwt user=delegatedUser(delegated);
                requireUnexpired(user);
                requireDocumentService(service);
                decision=operationService.equals("document-service")
                        ? canary.checkContent(session(user),subject(user),request.accountId(),request.organizationId(),
                                request.groupId(),request.operationKey(),request.exactResourceAccess())
                        : canary.check(session(user),subject(user),request.accountId(),request.organizationId(),
                                request.groupId(),request.operationKey());
            }
            ProfessionalSpiceDbCanary.Decision checked=decision;
            return execute(delegated, context -> {
                requireDocumentService(service);
                if(canary!=null) {
                    if(operationService.equals("document-service"))
                        canary.requireContentDecision(request.organizationId(),request.groupId(),request.operationKey(),
                                request.exactResourceAccess(),checked);
                    else canary.requireDecision(request.organizationId(),request.groupId(),request.operationKey(),checked);
                }
                OperationAuthorizationResponse response=checked!=null
                        && (checked.enforcing() || operationService.equals("document-service"))
                        ? canary.revalidate(checked,context,request.accountId(),request.organizationId())
                        : professional.require(context,request.accountId(),request.organizationId(),
                                request.groupId(),operationService,request.operationKey(),request.exactResourceAccess());
                if(checked!=null && !checked.enforcing() && operationService.equals("auth-service"))
                    canary.revalidate(checked,context,request.accountId(),request.organizationId());
                requireDocumentService(service);
                return response;
            });
        }
        OperationPolicyCandidate candidate = candidates.find(request.operationKey()).orElse(null);
        IndividualSpiceDbGuard.Decision individualDecision = prepareIndividual(delegatedUser(delegated), request.accountId(),
                request.operationKey(), request.groupId(), "document-service");
        Evaluation result = execute(delegated, context -> {
            requireDocumentService(service);
            Evaluation value = evaluateIndividual(context, request.accountId(), request.operationKey(), request.groupId(), "document-service", candidate,
                    individualDecision, false);
            requireDocumentService(service);
            return value;
        });
        candidates.put(result.candidate());
        return result.response();
    }

    /** Trusted IAM use cases already hold the selected session/account-group fence. */
    @Transactional(propagation = Propagation.MANDATORY)
    public OperationAuthorizationResponse authorizeIndividual(SessionAccess.Context context, UUID accountId,
            String operationKey, UUID groupId) {
        registry.require("auth-service", operationKey, "GROUP");
        return evaluateIndividual(context, accountId, operationKey, groupId, "auth-service", null).response();
    }

    /**
     * Prepares selected personal group operations before the command transaction starts.
     * @param jwt verified product token
     * @param account selected personal account
     * @param operation registered IAM group operation
     * @param group optional exact personal group
     * @return request-local graph evidence, or null outside the cohort
     */
    public IndividualSpiceDbGuard.Decision prepareIndividual(Jwt jwt, UUID account, String operation, UUID group) {
        return prepareIndividual(jwt, account, operation, group, "auth-service");
    }

    /**
     * Rechecks current SQL admission and consumes the exact preflight witness in the command transaction.
     * @param context locked selected-session context
     * @param account selected personal account
     * @param operation registered IAM operation
     * @param group optional exact personal group
     * @param decision request-local graph witness
     * @return immediate-expiry IAM evidence
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public OperationAuthorizationResponse authorizeIndividual(SessionAccess.Context context, UUID account,
            String operation, UUID group, IndividualSpiceDbGuard.Decision decision) {
        registry.require("auth-service", operation, "GROUP");
        return evaluateIndividual(context, account, operation, group, "auth-service", null, decision, false).response();
    }

    /** @param jwt current token @param account selected account @param operation operation key @param group exact group @param service operation owner @return graph witness */
    private IndividualSpiceDbGuard.Decision prepareIndividual(Jwt jwt, UUID account, String operation, UUID group, String service) {
        if (individual == null || !individual.applies(account)) return null;
        requireUnexpired(jwt);
        Evaluation prepared;
        try {
            prepared = access.execute(session(jwt), subject(jwt), context -> {
                requireUnexpired(jwt);
                Evaluation value = evaluateIndividual(context, account, operation, group, service, null, null, true);
                requireUnexpired(jwt);
                return value;
            });
        } catch (org.springframework.dao.DataAccessException dependency) {
            throw new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE, "CURRENT_POLICY_UNAVAILABLE");
        }
        IndividualSpiceDbGuard.Decision decision = individual.check(prepared.input(), jwt.getExpiresAt());
        requireUnexpired(jwt);
        return decision;
    }

    /**
     * Checks sharing admission in short IAM transactions around external graph evaluation.
     * @param service authenticated Document service
     * @param delegated current product-user token
     * @param request verified tenant, actor and recipient selectors
     * @return immediate recipient eligibility, never a resource grant
     * @throws OperationAuthorizationFailure when authority, tenant classification or graph evidence changes
     */
    @PreAuthorize("hasAuthority('SCOPE_iam.authorization.read')")
    public ProfessionalRecipientResponse professionalRecipient(Authentication service,String delegated,ProfessionalRecipientRequest request) {
        requireDocumentService(service);
        Jwt user=delegatedUser(delegated);
        String operation="EDIT".equals(request.accessMode())?"file.share.edit":"file.share.view";
        boolean institutional=access.execute(session(user),subject(user),context->{
            requireDocumentService(service);requireUnexpired(user);
            return students.institutional(request.organizationId());
        });
        ProfessionalSpiceDbCanary.Decision decision=null;
        if(canary!=null && !institutional
                && canary.applies(request.organizationId(),operation)) {
            requireUnexpired(user);
            decision=canary.checkContent(session(user),subject(user),request.accountId(),request.organizationId(),
                    request.groupId(),operation,false);
        }
        ProfessionalSpiceDbCanary.Decision sharingDecision=decision;
        List<UUID> targetGroups=jdbc.query("SELECT account_group_id FROM account_group_member WHERE account_id=? AND status='LINKED'",
                (row,index)->uuid(row.getBytes(1)),bytes(request.recipientAccountId()));
        if(targetGroups.size()!=1) throw denied("INELIGIBLE_RECIPIENT");
        return access.executeForGroups(session(user),subject(user),targetGroups,context->{
            requireDocumentService(service);requireUnexpired(user);
            if(institutional!=students.institutional(request.organizationId()))
                throw new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE,"AUTHORIZATION_CONTEXT_CHANGED");
            UUID recipient;
            if(institutional) {
                students.require(context,request.accountId(),request.organizationId(),request.groupId(),"document-service",
                        "EDIT".equals(request.accessMode())?"file.share.edit":"file.share.view");
                recipient=students.recipient(request.organizationId(),request.groupId(),request.recipientAccountId(),request.accessMode());
            } else {
                if(canary!=null)canary.requireContentDecision(request.organizationId(),request.groupId(),operation,false,sharingDecision);
                if(sharingDecision!=null)canary.revalidate(sharingDecision,context,request.accountId(),request.organizationId());
                else professional.require(context,request.accountId(),request.organizationId(),request.groupId(),
                        "document-service",operation);
                recipient=professional.recipient(request.organizationId(),request.groupId(),request.recipientAccountId(),request.accessMode());
            }
            requireDocumentService(service);requireUnexpired(user);
            Instant checked=clock.instant();
            return new ProfessionalRecipientResponse(request.accountId(),request.organizationId(),request.groupId(),request.recipientAccountId(),recipient,request.accessMode(),checked,checked);
        });
    }

    @PreAuthorize("hasAuthority('SCOPE_iam.authorization.read')")
    public IndividualRecipientResponse recipient(Authentication service, String delegated, IndividualRecipientRequest request) {
        requireDocumentService(service);
        // Recipient account-group locks join the normal ordered account-group fence, avoiding cross-group deadlocks.
        Jwt user = delegatedUser(delegated);
        IndividualSpiceDbGuard.Decision individualDecision = prepareIndividual(user, request.accountId(),
                "file.share", request.groupId(), "document-service");
        List<UUID> recipientGroups = jdbc.query("SELECT account_group_id FROM account_group_member WHERE account_id=? AND status='LINKED'",
                (result, row) -> uuid(result.getBytes(1)), bytes(request.recipientAccountId()));
        if (recipientGroups.size() != 1) throw denied("INELIGIBLE_RECIPIENT");
        return access.executeForGroups(session(user), subject(user), recipientGroups, context -> {
            requireDocumentService(service);
            requireUnexpired(user);
            requireIndividual(context, request.accountId());
            if (individual != null && individual.applies(request.accountId()))
                evaluateIndividual(context, request.accountId(), "file.share", request.groupId(), "document-service", null, individualDecision, false);
            List<UUID> recipients = jdbc.query("""
                    SELECT a.user_id FROM user_account a JOIN users u ON u.id=a.user_id
                    JOIN account_group_member m ON m.account_id=a.id AND m.status='LINKED'
                    JOIN account_group g ON g.id=m.account_group_id AND g.status='ACTIVE' AND g.user_id=a.user_id
                    WHERE a.id=? AND g.id=? AND a.type='PERSONAL' AND a.status='ACTIVE' AND u.status='ACTIVE'
                    FOR SHARE
                    """, (result, row) -> uuid(result.getBytes(1)), bytes(request.recipientAccountId()), bytes(recipientGroups.getFirst()));
            if (recipients.size() != 1) throw denied("INELIGIBLE_RECIPIENT");
            if (request.groupId() != null) {
                jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR SHARE", Long.class);
                String relationship = requireGroup(context, request.accountId(), request.groupId(), "file.share", true);
                if (relationship == null) throw denied("GROUP_MEMBERSHIP_REQUIRED");
                Boolean member = jdbc.queryForObject("""
                        SELECT EXISTS(SELECT 1 FROM personal_group_member m JOIN iam_group g ON g.id=m.group_id
                          WHERE m.group_id=? AND m.account_id=? AND m.status='ACTIVE'
                            AND g.workspace_context='INDIVIDUAL' AND g.status='ACTIVE')
                        """, Boolean.class, bytes(request.groupId()), bytes(request.recipientAccountId()));
                if (!Boolean.TRUE.equals(member)) throw denied("GROUP_RECIPIENT_REQUIRED");
            }
            requireUnexpired(user);
            Instant checked = clock.instant();
            requireDocumentService(service);
            return new IndividualRecipientResponse(request.accountId(), request.recipientAccountId(), recipients.getFirst(), checked, checked, request.groupId());
        });
    }

    @PreAuthorize("hasAuthority('SCOPE_iam.authorization.read')")
    public PersonalGroupAuthorizationResponse personalGroup(Authentication service, String delegated, PersonalGroupAuthorizationRequest request) {
        requireDocumentService(service);
        IndividualSpiceDbGuard.Decision decision = prepareIndividual(delegatedUser(delegated), request.accountId(),
                "group.read", request.groupId(), "auth-service");
        return execute(delegated, context -> {
            requireDocumentService(service);
            evaluateIndividual(context, request.accountId(), "group.read", request.groupId(), "auth-service", null, decision, false);
            com.unidocs.auth.group.personal.PersonalGroupAccess.Membership membership = personalGroups
                    .require(new SessionAccess.Context(context.session(), context.owner(), context.grant(), clock.instant()), request.accountId(), request.groupId(), false);
            Instant checked = clock.instant();
            requireDocumentService(service);
            return new PersonalGroupAuthorizationResponse(request.accountId(), request.groupId(), membership.membershipId(),
                    membership.memberVersion(), membership.groupVersion(), membership.ownerAccountId(), membership.status(), membership.purgeAfter(), checked, checked);
        });
    }

    private Evaluation evaluateIndividual(SessionAccess.Context context, UUID accountId, String operationKey,
            UUID groupId, String serviceId, OperationPolicyCandidate candidate) {
        return evaluateIndividual(context, accountId, operationKey, groupId, serviceId, candidate, null, false);
    }

    /** @param context current locked session @param accountId personal account @param operationKey exact operation @param groupId optional exact group @param serviceId operation owner @param candidate optional immutable policy @param decision graph witness @param preparing whether this is the preflight SQL snapshot @return current evidence */
    private Evaluation evaluateIndividual(SessionAccess.Context context, UUID accountId, String operationKey,
            UUID groupId, String serviceId, OperationPolicyCandidate candidate, IndividualSpiceDbGuard.Decision decision, boolean preparing) {
        SessionAccountGrant grant = requireIndividual(context, accountId);
        Long revision = jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR SHARE", Long.class);
        if (revision == null) throw denied("POLICY_UNAVAILABLE");
        OperationPolicyCandidate current = candidate != null && candidate.catalogVersion() == revision
                ? candidate : loadCandidate(serviceId, operationKey, revision);
        OperationPolicySnapshot snapshot = current.snapshot();
        Set<UUID> localAuthorities = new HashSet<>(current.baselineAuthorityIds());
        if (groupId != null) {
            String relationship = requireGroup(context, accountId, groupId, operationKey, "auth-service".equals(serviceId));
            localAuthorities.addAll(groupAuthorities(relationship, snapshot));
        } else if (operationKey.startsWith("group.") && !Set.of("group.create", "group.read", "group.invitation.accept", "group.invitation.decline").contains(operationKey)) {
            throw denied("GROUP_SCOPE_REQUIRED");
        }
        Instant policyCheckedAt = clock.instant();
        boolean restricted = Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS(SELECT 1 FROM iam_operation_restriction WHERE operation_id=? AND category_key='INDIVIDUAL'
                  AND (account_id IS NULL OR account_id=?) AND status='ACTIVE' AND valid_from<=?
                  AND (valid_until IS NULL OR valid_until>?))
                """, Boolean.class, bytes(snapshot.operationId()), bytes(accountId), Timestamp.from(policyCheckedAt), Timestamp.from(policyCheckedAt)));
        Set<UUID> eligible = new HashSet<>(snapshot.categoryAuthorityIds());
        eligible.retainAll(localAuthorities);
        if (!snapshot.policy().matches(new OperationAuthorityEvidence(eligible, eligible, true, restricted))) throw denied("CAPABILITY_DENIED");
        IndividualSpiceDbGuard.Input input = individual == null ? null : individual.capture(accountId, groupId, current, localAuthorities);
        if (input != null && !preparing) {
            eligible.retainAll(individual.revalidate(input, decision));
            if (!snapshot.policy().matches(new OperationAuthorityEvidence(eligible, eligible, true, restricted))) throw denied("CAPABILITY_DENIED");
            Instant completionDeadline = java.util.stream.Stream.of(context.session().expiresAt(), grant.idleExpiresAt(), grant.absoluteExpiresAt())
                    .min(Instant::compareTo).orElseThrow();
            List<Timestamp> boundaries = jdbc.query("""
                    SELECT MIN(boundary) FROM (
                      SELECT valid_from boundary FROM iam_operation_restriction
                      WHERE operation_id=? AND category_key='INDIVIDUAL' AND (account_id IS NULL OR account_id=?)
                        AND status='ACTIVE' AND valid_from>?
                      UNION ALL SELECT valid_until boundary FROM iam_operation_restriction
                      WHERE operation_id=? AND category_key='INDIVIDUAL' AND (account_id IS NULL OR account_id=?)
                        AND status='ACTIVE' AND valid_until>?
                    ) scheduled
                    """, (row, index) -> row.getTimestamp(1), bytes(snapshot.operationId()), bytes(accountId), Timestamp.from(policyCheckedAt),
                    bytes(snapshot.operationId()), bytes(accountId), Timestamp.from(policyCheckedAt));
            if (!boundaries.isEmpty() && boundaries.getFirst() != null && boundaries.getFirst().toInstant().isBefore(completionDeadline))
                completionDeadline = boundaries.getFirst().toInstant();
            Instant deadline = completionDeadline;
            org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
                    new org.springframework.transaction.support.TransactionSynchronization() {
                        /** Scheduled restrictions and selected-session expiry cannot be extended by command duration. */
                        @Override public void beforeCommit(boolean readOnly) {
                            if (!clock.instant().isBefore(deadline)) throw new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE,"INDIVIDUAL_EVIDENCE_EXPIRED");
                        }
                    });
        }
        Instant checked = clock.instant();
        sessions.touch(context.session(), grant, checked);
        OperationAuthorizationResponse response = new OperationAuthorizationResponse(accountId, context.owner().userId(), context.session().id(),
                snapshot.operationId(), operationKey, "INDIVIDUAL", snapshot.policyId(), snapshot.policy().matchMode(),
                keys(snapshot.policy().requiredAuthorityIds(), current.authorityKeys()), keys(eligible, current.authorityKeys()),
                snapshot.operationVersion(), snapshot.policyVersion(), snapshot.categoryBindingVersion(), snapshot.categoryRoleVersion(),
                revision, snapshot.authorityVersions(), checked, checked, "ALLOWED");
        return new Evaluation(response, current, input);
    }

    private OperationPolicyCandidate loadCandidate(String serviceId, String operationKey, long revision) {
        OperationPolicySnapshot snapshot = policies.findCurrent(serviceId, operationKey, "INDIVIDUAL")
                .orElseThrow(() -> denied("POLICY_DISABLED"));
        Map<UUID, String> keys = new HashMap<>();
        Set<UUID> baseline = new HashSet<>();
        jdbc.query("""
                SELECT a.id,a.authority_key,ra.authority_id baseline_authority
                FROM iam_policy_authority pa JOIN iam_authority a ON a.id=pa.authority_id AND a.service_id=pa.service_id
                LEFT JOIN iam_context_member_role_binding b ON b.category_key='INDIVIDUAL' AND b.status='ACTIVE'
                LEFT JOIN iam_role r ON r.id=b.role_id AND r.status='ACTIVE'
                LEFT JOIN iam_role_authority ra ON ra.role_id=r.id AND ra.authority_id=a.id
                WHERE pa.policy_id=? ORDER BY pa.authority_slot LIMIT 65
                """, result -> {
                    UUID authority = uuid(result.getBytes("id")); keys.put(authority, result.getString("authority_key"));
                    if (result.getBytes("baseline_authority") != null) baseline.add(authority);
                }, bytes(snapshot.policyId()));
        return new OperationPolicyCandidate(snapshot, revision, keys, baseline);
    }

    private SessionAccountGrant requireIndividual(SessionAccess.Context context, UUID accountId) {
        if (accountId == null) throw denied("ACCOUNT_REQUIRED");
        SessionAccountGrant grant = sessions.liveGrant(context.session(), accountId, clock.instant())
                .orElseThrow(() -> denied("ACCOUNT_LOCKED"));
        List<String> types = jdbc.query("SELECT type FROM user_account WHERE id=? AND user_id=? AND status='ACTIVE' FOR SHARE",
                (result, row) -> result.getString(1), bytes(accountId), bytes(context.owner().userId()));
        if (types.size() != 1 || !"PERSONAL".equals(types.getFirst())) throw denied("INDIVIDUAL_ACCOUNT_REQUIRED");
        return grant;
    }

    private String requireGroup(SessionAccess.Context context, UUID accountId, UUID groupId, String operationKey, boolean iamOperation) {
        List<GroupEligibility> rows = jdbc.query("""
                SELECT g.created_by_account_id,g.status,g.purge_after,m.status member_status
                FROM iam_group g JOIN personal_group_member m ON m.group_id=g.id AND m.account_id=?
                WHERE g.id=? AND g.workspace_context='INDIVIDUAL' AND g.organization_id IS NULL
                """ + (iamOperation ? " FOR UPDATE" : " FOR SHARE"), (result, row) -> new GroupEligibility(uuid(result.getBytes("created_by_account_id")), result.getString("status"),
                    result.getString("member_status"), result.getTimestamp("purge_after")), bytes(accountId), bytes(groupId));
        if (rows.size() != 1 || !"ACTIVE".equals(rows.getFirst().memberStatus())) throw denied("GROUP_MEMBERSHIP_REQUIRED");
        GroupEligibility row = rows.getFirst();
        boolean closing = "CLOSING".equals(row.status());
        boolean recover = Set.of("group.read", "group.delete.cancel", "file.read", "file.download", "file.copy", "folder.read", "folder.copy", "workspace.read", "deletion.read", "quota.read").contains(operationKey);
        Timestamp deadline = row.deadline();
        if (!"ACTIVE".equals(row.status()) && !("PREPARING".equals(row.status()) && recover)
                && !(closing && recover && deadline != null && clock.instant().isBefore(deadline.toInstant()))) {
            throw denied("GROUP_UNAVAILABLE");
        }
        if (closing && deadline != null && individual != null && individual.applies(accountId)) {
            org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
                    new org.springframework.transaction.support.TransactionSynchronization() {
                        /** A group copy/recovery window remains the original captured deadline. */
                        @Override public void beforeCommit(boolean readOnly) {
                            if (!clock.instant().isBefore(deadline.toInstant())) throw denied("GROUP_UNAVAILABLE");
                        }
                    });
        }
        return accountId.equals(row.ownerAccountId()) ? "OWNER" : "MEMBER";
    }

    private Set<UUID> groupAuthorities(String relationship, OperationPolicySnapshot snapshot) {
        return new HashSet<>(jdbc.query("""
                SELECT pa.authority_id FROM iam_group_relationship_role_binding b
                JOIN iam_role r ON r.id=b.role_id AND r.status='ACTIVE'
                JOIN iam_role_authority ra ON ra.role_id=r.id
                JOIN iam_policy_authority pa ON pa.authority_id=ra.authority_id AND pa.policy_id=?
                WHERE b.relationship_key=? AND b.status='ACTIVE' LIMIT 64
                """, (result, row) -> uuid(result.getBytes(1)), bytes(snapshot.policyId()), relationship));
    }

    private <T> T execute(String delegated, Function<SessionAccess.Context, T> operation) {
        Jwt user = delegatedUser(delegated);
        try {
            return access.execute(session(user), subject(user), context -> {
                requireUnexpired(user);
                T value = operation.apply(context);
                requireUnexpired(user); // Global/group lock contention cannot extend token validity.
                metrics.counter("authorization.operation", "outcome", "allowed").increment();
                return value;
            });
        } catch (OperationAuthorizationFailure denial) {
            metrics.counter("authorization.operation", "outcome", "denied").increment(); throw denial;
        } catch (org.springframework.dao.DataAccessException unavailable) {
            metrics.counter("authorization.operation", "outcome", "unavailable").increment();
            throw new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE, "CURRENT_POLICY_UNAVAILABLE");
        }
    }

    private Jwt delegatedUser(String header) {
        if (header == null || !header.startsWith("Bearer ") || header.length() > 8192 || header.length() <= 7
                || header.substring(7).chars().anyMatch(Character::isWhitespace)) throw new AuthenticationFailure();
        try { Jwt user = users.decode(header.substring(7)); session(user); subject(user); return user; }
        catch (JwtException | IllegalArgumentException malformed) { throw new AuthenticationFailure(); }
    }
    private void requireUnexpired(Jwt user) {
        if (user.getExpiresAt() == null || !clock.instant().isBefore(user.getExpiresAt())) throw new AuthenticationFailure();
    }
    /**
     * Rechecks service identity, expiry and scope even when an application method bypasses a Spring proxy.
     * @param authentication verified service caller bound to the current security context
     * @throws OperationAuthorizationFailure when service admission is absent or no longer current
     */
    private void requireDocumentService(Authentication authentication) {
        if (authentication != org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication()
                || !(authentication instanceof JwtAuthenticationToken token) || !token.isAuthenticated()
                || token.getAuthorities().stream().noneMatch(authority -> "SCOPE_iam.authorization.read".equals(authority.getAuthority()))
                || token.getToken().getExpiresAt() == null || !clock.instant().isBefore(token.getToken().getExpiresAt())
                || !("document-service".equals(token.getToken().getClaimAsString("azp")) || "document-service".equals(token.getName()))) {
            throw denied("SERVICE_OPERATION_NOT_ALLOWED");
        }
    }
    private static UUID session(Jwt user) { return UUID.fromString(user.getClaimAsString("sid")); }
    private static UUID subject(Jwt user) { return UUID.fromString(user.getSubject()); }
    private static UUID uuid(byte[] value) { ByteBuffer buffer = ByteBuffer.wrap(value); return new UUID(buffer.getLong(), buffer.getLong()); }
    private static Set<String> keys(Set<UUID> ids, Map<UUID, String> keys) { Set<String> result = new HashSet<>(); for (UUID id : ids) result.add(keys.get(id)); return result; }
    private static OperationAuthorizationFailure denied(String reason) { return new OperationAuthorizationFailure(HttpStatus.FORBIDDEN, reason); }
    private record Evaluation(OperationAuthorizationResponse response, OperationPolicyCandidate candidate, IndividualSpiceDbGuard.Input input) { }
    private record GroupEligibility(UUID ownerAccountId, String status, String memberStatus, Timestamp deadline) { }
}
