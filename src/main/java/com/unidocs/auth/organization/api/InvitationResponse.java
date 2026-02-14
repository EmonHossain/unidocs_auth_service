package com.unidocs.auth.organization.api;

import java.time.Instant;
import java.util.UUID;
import com.unidocs.auth.organization.domain.OrganizationInvitation;

public record InvitationResponse(UUID id, UUID organizationId, OrganizationInvitation.Status status, Instant expiresAt) { }
