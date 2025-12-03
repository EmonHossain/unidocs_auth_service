package com.unidocs.auth.authorization.api;

import java.time.Instant;
import java.util.UUID;

public record InternalAccountAuthorizationResponse(UUID accountId, UUID userId, UUID sessionId, String authMethod,
        long credentialVersion, Instant checkedAt, Instant expiresAt, String accountType,UUID organizationId) {
    public InternalAccountAuthorizationResponse(UUID accountId,UUID userId,UUID sessionId,String authMethod,long credentialVersion,
            Instant checkedAt,Instant expiresAt,String accountType) {
        this(accountId,userId,sessionId,authMethod,credentialVersion,checkedAt,expiresAt,accountType,null);
    }
}
