package com.unidocs.auth.authorization.api;

import java.time.Instant;
import java.util.UUID;
import com.unidocs.auth.organization.domain.OrganizationMembership;

/** Current IAM membership evidence, never a workspace/document permission grant. */
public record InternalAuthorizationResponse(UUID accountId, UUID organizationId, UUID membershipId,
        OrganizationMembership.Role role, long membershipVersion, long authorizationVersion,
        Instant checkedAt, Instant expiresAt) { }
