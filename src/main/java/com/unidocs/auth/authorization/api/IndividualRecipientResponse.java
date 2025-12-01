package com.unidocs.auth.authorization.api;

import java.time.Instant;
import java.util.UUID;

public record IndividualRecipientResponse(UUID accountId, UUID recipientAccountId, UUID recipientUserId,
        Instant checkedAt, Instant validUntil, UUID groupId) { }
