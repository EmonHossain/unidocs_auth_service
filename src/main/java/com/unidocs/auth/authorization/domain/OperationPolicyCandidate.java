package com.unidocs.auth.authorization.domain;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Reusable policy payload only; its revision must be fenced against current MySQL on every operation. */
public record OperationPolicyCandidate(OperationPolicySnapshot snapshot, long catalogVersion,
        Map<UUID, String> authorityKeys, Set<UUID> baselineAuthorityIds) {
    public OperationPolicyCandidate {
        authorityKeys = Map.copyOf(authorityKeys);
        baselineAuthorityIds = Set.copyOf(baselineAuthorityIds);
        if (catalogVersion < 1 || !authorityKeys.keySet().equals(snapshot.policy().requiredAuthorityIds())) {
            throw new IllegalArgumentException("Incomplete policy candidate");
        }
    }
}
