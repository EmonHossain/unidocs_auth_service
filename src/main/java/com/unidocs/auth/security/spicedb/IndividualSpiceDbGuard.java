package com.unidocs.auth.security.spicedb;

import com.authzed.api.v1.CheckPermissionRequest;
import com.authzed.api.v1.CheckPermissionResponse;
import com.authzed.api.v1.Consistency;
import com.authzed.api.v1.ObjectReference;
import com.authzed.api.v1.SubjectReference;
import com.authzed.api.v1.ZedToken;
import com.unidocs.auth.authorization.application.OperationAuthorizationFailure;
import com.unidocs.auth.authorization.domain.OperationPolicyCandidate;
import com.unidocs.auth.authorization.domain.OperationAuthorityEvidence;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Request-local strict intersection for an explicitly selected PERSONAL cohort. */
@Component
public final class IndividualSpiceDbGuard {
    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final SpiceDbPermissionClient graph;
    private final boolean enabled;
    private final Set<UUID> accounts;
    private final io.micrometer.core.instrument.MeterRegistry metrics;

    /**
     * Configures the personal release independently of professional enforcement.
     * @param jdbc owning IAM storage
     * @param clock current eligibility clock
     * @param clients optional check-only graph client
     * @param environment explicit, default-disabled cohort configuration
     * @param metrics bounded operation outcomes and duration
     * @throws IllegalStateException for incomplete enabled configuration
     */
    public IndividualSpiceDbGuard(JdbcTemplate jdbc, Clock clock,
            ObjectProvider<SpiceDbPermissionClient> clients, Environment environment, io.micrometer.core.instrument.MeterRegistry metrics) {
        this.jdbc = jdbc;
        this.clock = clock;
        graph = clients.getIfAvailable();
        this.metrics = metrics;
        enabled = environment.getProperty("auth.spicedb.individual.enabled", Boolean.class, false);
        accounts = Arrays.stream(environment.getProperty("auth.spicedb.individual.account-ids", "").split(","))
                .map(String::strip).filter(value -> !value.isEmpty()).map(UUID::fromString)
                .collect(Collectors.toUnmodifiableSet());
        if (enabled && (graph == null || accounts.isEmpty() || accounts.size() > 20))
            throw new IllegalStateException("Individual enforcement requires a graph client and 1..20 personal accounts.");
    }

    /** @param account selected account @return whether the server selected this account */
    public boolean applies(UUID account) { return enabled && accounts.contains(account); }

    /** Immutable SQL dependency fingerprint; it carries no reusable authorization. */
    public record Input(String snapshot, UUID account, OperationPolicyCandidate candidate) { }

    /** Operation-local graph witness; constructing one does not skip current SQL admission. */
    public record Decision(String snapshot, UUID account, Set<UUID> authorities, Instant checkedAt, Instant expiresAt) {
        public Decision { authorities = Set.copyOf(authorities); }
    }

    /**
     * Persists bounded tuple intent alongside a coherent current SQL policy read.
     * SQL identity, group membership, restrictions and lifecycle must already have passed.
     * @param account verified PERSONAL account
     * @param group optional exact personal group
     * @param candidate current locked policy dependencies
     * @param local current baseline plus exact-group authority UUIDs
     * @return immutable source evidence, or null outside the selected cohort
     */
    public Input capture(UUID account, UUID group, OperationPolicyCandidate candidate, Set<UUID> local) {
        if (!applies(account)) return null;
        if (!TransactionSynchronizationManager.isActualTransactionActive()) throw new IllegalStateException("SQL snapshot required.");
        if (candidate.snapshot().policy().requiredAuthorityIds().size() > 64) throw unavailable();
        String canonical = account + ":" + group + ":" + candidate.catalogVersion() + ":"
                + candidate.snapshot().operationId() + ":" + candidate.snapshot().policyId() + ":"
                + ordered(candidate.snapshot().categoryAuthorityIds()) + ":" + ordered(local);
        String id = hash(canonical);
        jdbc.update("INSERT IGNORE INTO iam_individual_graph_intent(snapshot_id,account_id,group_id,created_at) VALUES(?,?,?,?)",
                id, bytes(account), group == null ? null : bytes(group), Timestamp.from(clock.instant()));
        for (UUID authority : candidate.snapshot().policy().requiredAuthorityIds()) {
            jdbc.update("""
                    INSERT IGNORE INTO iam_individual_graph_authority
                    (snapshot_id,authority_id,category_granted,local_granted) VALUES(?,?,?,?)
                    """, id, bytes(authority), candidate.snapshot().categoryAuthorityIds().contains(authority), local.contains(authority));
        }
        return new Input(id, account, candidate);
    }

    /**
     * Checks each required UUID at one fresh pinned revision outside database transactions.
     * @param input committed immutable tuple intent from current SQL
     * @param tokenExpiresAt delegated product token deadline
     * @return a bounded request-local same-authority witness
     * @throws OperationAuthorizationFailure when projection, snapshot or permission is unavailable
     */
    public Decision check(Input input, Instant tokenExpiresAt) {
        if (input == null) return null;
        if (TransactionSynchronizationManager.isActualTransactionActive()) throw new IllegalStateException("Graph checks outside SQL only.");
        Instant started = clock.instant();
        long timer = System.nanoTime();
        Instant until = started.plusSeconds(5).isBefore(tokenExpiresAt) ? started.plusSeconds(5) : tokenExpiresAt;
        try {
            List<String> tokens = jdbc.query("SELECT zed_token FROM iam_individual_graph_intent WHERE snapshot_id=? AND applied_at IS NOT NULL",
                    (row, index) -> row.getString(1), input.snapshot());
            if (tokens.size() != 1 || tokens.getFirst() == null || tokens.getFirst().isBlank()) throw unavailable();
            Set<UUID> matched = new HashSet<>();
            ZedToken pinned = null;
            for (UUID authority : input.candidate().snapshot().policy().requiredAuthorityIds().stream().sorted().toList()) {
                if (clock.instant().isBefore(started) || !clock.instant().isBefore(until)) throw unavailable();
                CheckPermissionResponse result = graph.checkPermission(CheckPermissionRequest.newBuilder()
                        .setResource(ObjectReference.newBuilder().setObjectType("individual_capability")
                                .setObjectId(input.snapshot() + "_" + authority))
                        .setPermission("grant")
                        .setSubject(SubjectReference.newBuilder().setObject(ObjectReference.newBuilder()
                                .setObjectType("account").setObjectId(input.account().toString())))
                        .setConsistency(pinned == null ? Consistency.newBuilder().setFullyConsistent(true).build()
                                : Consistency.newBuilder().setAtExactSnapshot(pinned).build()).build());
                if (!result.hasCheckedAt() || result.getCheckedAt().getToken().isBlank()
                        || pinned != null && !pinned.equals(result.getCheckedAt())) throw unavailable();
                if (pinned == null) pinned = result.getCheckedAt();
                if (result.getPermissionship() == CheckPermissionResponse.Permissionship.PERMISSIONSHIP_HAS_PERMISSION)
                    matched.add(authority);
                else if (result.getPermissionship() != CheckPermissionResponse.Permissionship.PERMISSIONSHIP_NO_PERMISSION)
                    throw unavailable();
            }
            if (!input.candidate().snapshot().policy().matches(new OperationAuthorityEvidence(matched, matched, true, false)))
                throw new OperationAuthorizationFailure(HttpStatus.FORBIDDEN, "INDIVIDUAL_CAPABILITY_DENIED");
            Decision decision = new Decision(input.snapshot(), input.account(), matched, started, until);
            current(decision);
            metrics.counter("authorization.individual.checks", "outcome", "allowed").increment();
            return decision;
        } catch (io.grpc.StatusRuntimeException | org.springframework.dao.DataAccessException dependency) {
            metrics.counter("authorization.individual.checks", "outcome", "unavailable").increment();
            throw unavailable();
        } catch (OperationAuthorizationFailure rejection) {
            metrics.counter("authorization.individual.checks", "outcome", "rejected").increment();
            throw rejection;
        } finally {
            metrics.timer("authorization.individual.check.duration").record(System.nanoTime() - timer, java.util.concurrent.TimeUnit.NANOSECONDS);
        }
    }

    /**
     * Rejects bypasses and changed SQL dependencies under the final owning transaction.
     * @param input freshly recaptured current policy, account and exact-group evidence
     * @param decision preflight graph decision
     * @return graph-matched UUIDs to intersect with current SQL evidence
     */
    public Set<UUID> revalidate(Input input, Decision decision) {
        if (input == null) {
            if (decision != null) throw unavailable();
            return Set.of();
        }
        if (decision == null || !input.snapshot().equals(decision.snapshot()) || !input.account().equals(decision.account()))
            throw unavailable();
        current(decision);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            /** Fences lock waits and mutation duration before commit. */
            @Override public void beforeCommit(boolean readOnly) { current(decision); }
        });
        return decision.authorities();
    }

    /** @param decision operation deadline that a lock wait cannot extend */
    private void current(Decision decision) {
        Instant now = clock.instant();
        if (now.isBefore(decision.checkedAt()) || !now.isBefore(decision.expiresAt())) throw unavailable();
    }

    /** @param values stable UUID set @return deterministic dependency encoding */
    private static String ordered(Set<UUID> values) { return values.stream().sorted().map(UUID::toString).collect(Collectors.joining(",")); }

    /** @param value immutable source dependency encoding @return content-qualified graph generation */
    private static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    /** @return safe fail-closed dependency result */
    static OperationAuthorizationFailure unavailable() {
        return new OperationAuthorizationFailure(HttpStatus.SERVICE_UNAVAILABLE, "INDIVIDUAL_GRAPH_UNAVAILABLE");
    }
}
