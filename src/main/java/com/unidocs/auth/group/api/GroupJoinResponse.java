package com.unidocs.auth.group.api;

import java.time.Instant;
import java.util.UUID;
import com.unidocs.auth.group.domain.GroupJoinRequest;

public record GroupJoinResponse(UUID id, UUID organizationId, UUID groupId, UUID accountId, UUID organizationMembershipId,
        String requestedRole, String reason, GroupJoinRequest.Status status, long version, UUID reviewedBy,
        Instant reviewedAt, String reviewReason, UUID membershipId, Instant createdAt, Instant updatedAt) {
    public static GroupJoinResponse from(GroupJoinRequest request) {
        return new GroupJoinResponse(request.id(),request.organizationId(),request.groupId(),request.accountId(),request.organizationMembershipId(),
                request.requestedRole(),request.reason(),request.status(),request.version(),request.reviewedBy(),request.reviewedAt(),request.reviewReason(),
                request.membershipId(),request.createdAt(),request.updatedAt());
    }
}
