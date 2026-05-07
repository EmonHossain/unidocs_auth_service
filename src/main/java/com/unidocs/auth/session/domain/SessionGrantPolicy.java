package com.unidocs.auth.session.domain;

import java.time.Duration;
import java.time.Instant;

public record SessionGrantPolicy(Duration idleTimeout, Duration absoluteTimeout, long version) {
    public SessionGrantPolicy {
        if (idleTimeout == null || absoluteTimeout == null || idleTimeout.isZero() || idleTimeout.isNegative()
                || absoluteTimeout.compareTo(idleTimeout) < 0 || absoluteTimeout.compareTo(UserSession.LIFETIME) > 0 || version < 1) {
            throw new IllegalArgumentException("Invalid session grant policy.");
        }
    }
    public Instant absoluteExpiry(Instant now, UserSession session) {
        Instant proposed = now.plus(absoluteTimeout);
        return proposed.isBefore(session.expiresAt()) ? proposed : session.expiresAt();
    }
    public Instant idleExpiry(Instant now, Instant absolute) {
        Instant proposed = now.plus(idleTimeout);
        return proposed.isBefore(absolute) ? proposed : absolute;
    }
}
