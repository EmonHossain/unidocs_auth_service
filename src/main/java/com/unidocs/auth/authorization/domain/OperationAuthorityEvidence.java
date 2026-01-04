package com.unidocs.auth.authorization.domain;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Authority evidence resolved from the selected context and applicable scope only. */
public record OperationAuthorityEvidence(
        Set<UUID> categoryAuthorityIds,
        Set<UUID> scopedAuthorityIds,
        boolean currentCoherent,
        boolean applicableExplicitDeny) {

    public OperationAuthorityEvidence {
        categoryAuthorityIds = Set.copyOf(Objects.requireNonNull(categoryAuthorityIds, "categoryAuthorityIds"));
        scopedAuthorityIds = Set.copyOf(Objects.requireNonNull(scopedAuthorityIds, "scopedAuthorityIds"));
    }
}
