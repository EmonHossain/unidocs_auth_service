package com.unidocs.auth.session.domain;

import java.time.Instant;
import java.time.Duration;
import java.util.UUID;

/** An account unlock, independent of navigation preference or organization permissions. */
public record SessionAccountGrant(UUID sessionId, UUID accountId, String status, String authMethod,
        long credentialVersion, Instant idleExpiresAt, Instant absoluteExpiresAt) {
    public static final Duration IDLE_LIFETIME = Duration.ofMinutes(30);

    public boolean activeAt(Instant now, long currentCredentialVersion) {
        return "ACTIVE".equals(status) && credentialVersion == currentCredentialVersion
                && now.isBefore(idleExpiresAt) && now.isBefore(absoluteExpiresAt);
    }

    public Instant nextIdleExpiry(Instant now) {
        Instant expiry = now.plus(IDLE_LIFETIME);
        return expiry.isBefore(absoluteExpiresAt) ? expiry : absoluteExpiresAt;
    }
}
