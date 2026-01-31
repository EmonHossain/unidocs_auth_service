package com.unidocs.auth.group.domain;

import java.time.Instant;
import java.util.UUID;
import java.util.Objects;

public record GroupJoinRequest(UUID id, UUID organizationId, UUID groupId, UUID accountId,
        UUID organizationMembershipId, String requestedRole, String reason, Status status, long version,
        UUID reviewedBy, Instant reviewedAt, String reviewReason, UUID membershipId,
        Instant createdAt, Instant updatedAt) {
    public enum Status { PENDING, APPROVED, REJECTED, CANCELLED }
    public GroupJoinRequest {
        Objects.requireNonNull(id);Objects.requireNonNull(organizationId);Objects.requireNonNull(groupId);
        Objects.requireNonNull(accountId);Objects.requireNonNull(organizationMembershipId);Objects.requireNonNull(status);
        Objects.requireNonNull(createdAt);Objects.requireNonNull(updatedAt);
        requestedRole=GroupMembership.normalizedRole(requestedRole);reason=normalizedReason(reason);
        boolean reviewed=status==Status.APPROVED || status==Status.REJECTED;
        if(version<1 || (reviewed && (reviewedBy==null || reviewedAt==null || reviewReason==null))
                || (!reviewed && (reviewedBy!=null || reviewedAt!=null || reviewReason!=null || membershipId!=null))
                || (status==Status.APPROVED && membershipId==null) || (status==Status.REJECTED && membershipId!=null)) {
            throw new IllegalArgumentException("Invalid join decision.");
        }
        if(reviewed) reviewReason=normalizedReason(reviewReason);
    }
    public static String normalizedReason(String reason) {
        if (reason == null || reason.isBlank() || reason.strip().length() > 500
                || reason.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Invalid request reason.");
        }
        return reason.strip();
    }
    @Override public String toString() { return "GroupJoinRequest[id=" + id + ",status=" + status + "]"; }
}
