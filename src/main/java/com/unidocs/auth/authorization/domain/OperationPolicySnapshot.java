package com.unidocs.auth.authorization.domain;

import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Current catalog policy payload; session, membership and resource guards remain required. */
public record OperationPolicySnapshot(
        UUID operationId,
        String serviceId,
        String operationKey,
        long operationVersion,
        UUID policyId,
        long policyVersion,
        String categoryKey,
        long categoryBindingVersion,
        UUID categoryRoleId,
        long categoryRoleVersion,
        OperationAuthorityPolicy policy,
        Set<UUID> categoryAuthorityIds,
        Map<UUID, Long> authorityVersions) {

    public OperationPolicySnapshot {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(policyId, "policyId");
        Objects.requireNonNull(categoryRoleId, "categoryRoleId");
        requireStableKey(serviceId, "serviceId");
        requireStableKey(operationKey, "operationKey");
        requireKey(categoryKey, "categoryKey");
        requirePositiveVersion(operationVersion, "operationVersion");
        requirePositiveVersion(policyVersion, "policyVersion");
        requirePositiveVersion(categoryBindingVersion, "categoryBindingVersion");
        requirePositiveVersion(categoryRoleVersion, "categoryRoleVersion");
        Objects.requireNonNull(policy, "policy");
        categoryAuthorityIds = Set.copyOf(Objects.requireNonNull(categoryAuthorityIds, "categoryAuthorityIds"));
        authorityVersions = Map.copyOf(Objects.requireNonNull(authorityVersions, "authorityVersions"));
        if (!authorityVersions.keySet().equals(policy.requiredAuthorityIds())) {
            throw new IllegalArgumentException("Authority versions must cover exactly the required authorities");
        }
        if (!policy.requiredAuthorityIds().containsAll(categoryAuthorityIds)) {
            throw new IllegalArgumentException("Category authorities must be a subset of required authorities");
        }
        for (Long authorityVersion : authorityVersions.values()) {
            requirePositiveVersion(authorityVersion, "authorityVersion");
        }
    }

    private static void requireKey(String key, String name) {
        Objects.requireNonNull(key, name);
        if (key.isBlank() || !key.equals(key.strip())) {
            throw new IllegalArgumentException(name + " must be nonblank without surrounding whitespace");
        }
    }

    private static void requirePositiveVersion(long version, String name) {
        if (version <= 0) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }

    private static void requireStableKey(String key, String name) {
        requireKey(key, name);
        if (!key.matches("[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")) {
            throw new IllegalArgumentException(name + " must be a stable lowercase key");
        }
    }
}
