package com.unidocs.auth.authorization.domain;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * The authority-matching portion of an operation policy. A match is not a complete
 * authorization decision: authentication, session, membership and domain guards remain required.
 */
public record OperationAuthorityPolicy(
        Set<UUID> requiredAuthorityIds,
        AuthorityMatchMode matchMode,
        boolean requiresScopedAuthorities) {

    public static final int MAX_REQUIRED_AUTHORITIES = 64;

    public OperationAuthorityPolicy {
        requiredAuthorityIds = Set.copyOf(Objects.requireNonNull(requiredAuthorityIds, "requiredAuthorityIds"));
        Objects.requireNonNull(matchMode, "matchMode");
        if (requiredAuthorityIds.isEmpty() || requiredAuthorityIds.size() > MAX_REQUIRED_AUTHORITIES) {
            throw new IllegalArgumentException("An operation policy requires between 1 and "
                    + MAX_REQUIRED_AUTHORITIES + " authorities");
        }
    }

    public boolean matches(OperationAuthorityEvidence evidence) {
        if (evidence == null || !evidence.currentCoherent() || evidence.applicableExplicitDeny()) {
            return false;
        }
        for (UUID requiredAuthorityId : requiredAuthorityIds) {
            boolean matched = evidence.categoryAuthorityIds().contains(requiredAuthorityId)
                    && (!requiresScopedAuthorities || evidence.scopedAuthorityIds().contains(requiredAuthorityId));
            if (matchMode == AuthorityMatchMode.ALL_OF && !matched) {
                return false;
            }
            if (matchMode == AuthorityMatchMode.ANY_OF && matched) {
                return true;
            }
        }
        return matchMode == AuthorityMatchMode.ALL_OF;
    }
}
