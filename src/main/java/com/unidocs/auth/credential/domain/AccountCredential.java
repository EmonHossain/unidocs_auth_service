package com.unidocs.auth.credential.domain;

import java.time.Instant;
import java.util.UUID;

/** Additional account-root proof; password login remains authoritative in LoginIdentity. */
public record AccountCredential(UUID id, UUID accountId, String credentialHash, String status, long version,
        int failedAttempts, Instant lockedUntil) {
    public boolean usableAt(Instant now) {
        return "ACTIVE".equals(status) && (lockedUntil == null || !now.isBefore(lockedUntil));
    }
    @Override public String toString() { return "AccountCredential[REDACTED]"; }
}
