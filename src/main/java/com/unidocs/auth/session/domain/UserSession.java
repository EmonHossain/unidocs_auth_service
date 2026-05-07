package com.unidocs.auth.session.domain;

import java.time.Instant;
import java.util.UUID;

/** Durable umbrella session, mapped explicitly by SessionRepository. */
public record UserSession(UUID id, UUID accountGroupId, UUID loginAccountId, String status,
        Instant authenticatedAt, Instant lastActivityAt, Instant expiresAt, Instant revokedAt) {
    public static final java.time.Duration LIFETIME = java.time.Duration.ofHours(12);

    public boolean activeAt(Instant now) {
        return "ACTIVE".equals(status) && revokedAt == null && now.isBefore(expiresAt);
    }
}
