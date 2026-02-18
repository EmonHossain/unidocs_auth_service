package com.unidocs.auth.organization.api;
import java.time.Instant;
import java.util.UUID;
import com.unidocs.auth.organization.domain.Organization;
import com.unidocs.auth.organization.domain.OrganizationMembership;
public record OrganizationResponse(UUID id, String name, String slug, Organization.Type type, UUID membershipId,
        UUID accountId, OrganizationMembership.Role role, long membershipVersion, long authorizationVersion, Instant createdAt) { }
