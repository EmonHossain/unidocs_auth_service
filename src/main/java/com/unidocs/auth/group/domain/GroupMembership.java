package com.unidocs.auth.group.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** An assignment is effective only together with current organization and account authority. */
public record GroupMembership(UUID id, UUID organizationId, UUID groupId, UUID accountId,
        UUID organizationMembershipId, String role, MembershipType membershipType, Source source, String sourceReference,
        Status status, Instant validFrom, Instant validUntil, long version, Instant createdAt, Instant updatedAt, boolean canManageGroup) {
    public enum MembershipType { PERMANENT, TEMPORARY }
    public enum Source { ORGANIZATION_ASSIGNMENT, ADMIN_APPROVAL, OPEN_JOIN, COURSE_ENROLLMENT, INVITATION }
    public enum Status { ACTIVE, REVOKED }

    public GroupMembership(UUID id, UUID organizationId, UUID groupId, UUID accountId, UUID organizationMembershipId,
            String role, MembershipType membershipType, Source source, String sourceReference, Status status,
            Instant validFrom, Instant validUntil, long version, Instant createdAt, Instant updatedAt) {
        this(id,organizationId,groupId,accountId,organizationMembershipId,role,membershipType,source,sourceReference,status,
                validFrom,validUntil,version,createdAt,updatedAt,false);
    }
    public GroupMembership {
        Objects.requireNonNull(id);
        Objects.requireNonNull(organizationId);
        Objects.requireNonNull(groupId);
        Objects.requireNonNull(accountId);
        Objects.requireNonNull(organizationMembershipId);
        Objects.requireNonNull(source);
        Objects.requireNonNull(status);
        Objects.requireNonNull(validFrom);
        Objects.requireNonNull(createdAt);
        Objects.requireNonNull(updatedAt);
        role = normalizedRole(role);
        if (((source == Source.ORGANIZATION_ASSIGNMENT || source == Source.OPEN_JOIN) && sourceReference != null)
                || (source != Source.ORGANIZATION_ASSIGNMENT && source != Source.OPEN_JOIN && (sourceReference == null || !UUID.fromString(sourceReference).toString().equals(sourceReference)))) {
            throw new IllegalArgumentException("Invalid membership source.");
        }
        if (version < 1 || (validUntil != null && !validUntil.isAfter(validFrom))
                || membershipType != (validUntil == null ? MembershipType.PERMANENT : MembershipType.TEMPORARY)) {
            throw new IllegalArgumentException("Invalid group membership.");
        }
    }

    public static String normalizedRole(String role) {
        if (role == null || !role.strip().matches("[A-Za-z][A-Za-z0-9_.-]{0,63}")) {
            throw new IllegalArgumentException("Invalid group role.");
        }
        return role.strip();
    }

    public boolean effectiveAt(Instant now) {
        return status == Status.ACTIVE && !now.isBefore(validFrom) && (validUntil == null || now.isBefore(validUntil));
    }
}
