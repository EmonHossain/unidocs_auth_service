package com.unidocs.auth.authorization.api;

import java.time.Instant;
import java.util.UUID;

/** Immediate eligibility check, never an invitation, membership or reusable authorization lease. */
public record ProfessionalRecipientResponse(UUID accountId,UUID organizationId,UUID groupId,
        UUID recipientAccountId,UUID recipientUserId,String accessMode,Instant checkedAt,Instant validUntil) { }
