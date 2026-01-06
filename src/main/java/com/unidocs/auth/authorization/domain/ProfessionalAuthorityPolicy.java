package com.unidocs.auth.authorization.domain;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Pure professional authority matching, not an authentication or visibility decision.
 * The caller must resolve complete actor eligibility and resource ancestry from current
 * authoritative state. Never construct this evidence from client-supplied ancestry.
 */
public final class ProfessionalAuthorityPolicy {
    private ProfessionalAuthorityPolicy() { }

    public enum Level { ORGANIZATION, DEPARTMENT, TEAM }

    public record Scope(UUID organizationId, UUID departmentId, UUID teamId) {
        public Scope {
            Objects.requireNonNull(organizationId, "organizationId");
            if (teamId != null && departmentId == null) {
                throw new IllegalArgumentException("A team requires its verified department");
            }
        }

        public Level level() {
            return teamId != null ? Level.TEAM : departmentId != null ? Level.DEPARTMENT : Level.ORGANIZATION;
        }

        public boolean contains(Scope target) {
            return target != null && organizationId.equals(target.organizationId)
                    && (departmentId == null || departmentId.equals(target.departmentId))
                    && (teamId == null || teamId.equals(target.teamId));
        }
    }

    public record Assignment(UUID accountId, Scope scope, Set<UUID> authorityIds,
            Instant validFrom, Instant validUntil) {
        public Assignment {
            Objects.requireNonNull(accountId, "accountId");
            Objects.requireNonNull(scope, "scope");
            authorityIds = Set.copyOf(authorityIds);
            requireWindow(validFrom, validUntil);
        }
    }

    /** Null accountId restricts every actor in this scope; a deny targets the whole operation. */
    public record Restriction(UUID operationId, UUID accountId, Scope scope,
            Instant validFrom, Instant validUntil) {
        public Restriction {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(scope, "scope");
            requireWindow(validFrom, validUntil);
        }
    }

    public static boolean matches(OperationAuthorityPolicy policy, UUID operationId, UUID selectedAccountId,
            Scope resourceScope, Set<UUID> categoryAuthorities, List<Assignment> assignments,
            List<Restriction> restrictions, Instant checkedAt, boolean currentCoherent) {
        if (policy == null || !policy.requiresScopedAuthorities() || operationId == null
                || selectedAccountId == null || resourceScope == null || categoryAuthorities == null
                || assignments == null || restrictions == null || checkedAt == null || !currentCoherent) {
            return false;
        }
        Set<UUID> scoped = new HashSet<>();
        for (Assignment assignment : assignments) {
            if (assignment == null) return false;
            if (selectedAccountId.equals(assignment.accountId()) && assignment.scope().contains(resourceScope)
                    && active(assignment.validFrom(), assignment.validUntil(), checkedAt)) {
                scoped.addAll(assignment.authorityIds());
            }
        }
        for (Restriction restriction : restrictions) {
            if (restriction == null) return false;
            if (operationId.equals(restriction.operationId())
                    && (restriction.accountId() == null || selectedAccountId.equals(restriction.accountId()))
                    && restriction.scope().contains(resourceScope)
                    && active(restriction.validFrom(), restriction.validUntil(), checkedAt)) {
                return false;
            }
        }
        return policy.matches(new OperationAuthorityEvidence(categoryAuthorities, scoped, true, false));
    }

    private static boolean active(Instant from, Instant until, Instant now) {
        return !now.isBefore(from) && (until == null || now.isBefore(until));
    }

    private static void requireWindow(Instant from, Instant until) {
        Objects.requireNonNull(from, "validFrom");
        if (until != null && !until.isAfter(from)) {
            throw new IllegalArgumentException("Expiry must follow activation");
        }
    }
}
