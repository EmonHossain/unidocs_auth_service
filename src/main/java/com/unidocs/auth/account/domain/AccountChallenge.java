package com.unidocs.auth.account.domain;

import java.time.Instant;
import java.util.UUID;

public record AccountChallenge(UUID id, UUID sessionId, UUID accountId, Purpose purpose, Method method,
        String credentialSource, UUID credentialId, long credentialVersion, long policyVersion,
        String status, int attempts, Instant expiresAt) {
    public enum Purpose { UNLOCK, LINK, UNLINK, SET_PIN }
    public enum Method { PASSWORD, PIN, PASSKEY }
    public static final java.time.Duration LIFETIME = java.time.Duration.ofMinutes(2);
    public boolean pendingAt(Instant now) { return "PENDING".equals(status) && attempts < 5 && now.isBefore(expiresAt); }
}
