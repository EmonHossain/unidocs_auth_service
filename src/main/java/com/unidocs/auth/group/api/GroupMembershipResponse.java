package com.unidocs.auth.group.api;

import java.time.Instant;
import java.util.UUID;
import com.unidocs.auth.group.domain.GroupMembership;

public record GroupMembershipResponse(UUID id, UUID organizationId, UUID groupId, UUID accountId,
        UUID organizationMembershipId, String role, GroupMembership.MembershipType membershipType,
        GroupMembership.Source source, String sourceReference, GroupMembership.Status status, Instant validFrom, Instant validUntil,
        long version, Instant createdAt, Instant updatedAt, boolean effective, boolean canManageGroup) {
    public static GroupMembershipResponse from(GroupMembership membership, Instant now, boolean organizationAvailable) {
        return new GroupMembershipResponse(membership.id(), membership.organizationId(), membership.groupId(),
                membership.accountId(), membership.organizationMembershipId(), membership.role(), membership.membershipType(),
                membership.source(), membership.sourceReference(), membership.status(), membership.validFrom(), membership.validUntil(), membership.version(),
                membership.createdAt(), membership.updatedAt(), organizationAvailable && membership.effectiveAt(now), membership.canManageGroup());
    }
}
