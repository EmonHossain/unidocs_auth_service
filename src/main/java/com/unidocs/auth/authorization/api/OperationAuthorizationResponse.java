package com.unidocs.auth.authorization.api;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import com.unidocs.auth.authorization.domain.AuthorityMatchMode;

/** Immediate-expiry IAM evidence; Document must still enforce its own resource guards. */
public record OperationAuthorizationResponse(UUID accountId, UUID userId, UUID sessionId, UUID operationId,
        String operationKey, String categoryKey, UUID policyId, AuthorityMatchMode matchMode,
        Set<String> requiredAuthorities, Set<String> categoryAuthorities, long operationVersion, long policyVersion,
        long categoryBindingVersion, long categoryRoleVersion, long catalogVersion, Map<UUID, Long> authorityVersions,
        Instant checkedAt, Instant validUntil, String reasonCode) {
    public OperationAuthorizationResponse {
        requiredAuthorities = Set.copyOf(requiredAuthorities);
        categoryAuthorities = Set.copyOf(categoryAuthorities);
        authorityVersions = Map.copyOf(authorityVersions);
    }
}
