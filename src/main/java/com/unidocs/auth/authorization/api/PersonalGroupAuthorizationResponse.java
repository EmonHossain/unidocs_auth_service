package com.unidocs.auth.authorization.api;
import java.time.Instant;
import java.util.UUID;
public record PersonalGroupAuthorizationResponse(UUID accountId, UUID groupId, UUID membershipId,
        long memberVersion, long groupVersion, UUID ownerAccountId, String status, Instant purgeAfter,
        Instant checkedAt, Instant validUntil) { }
