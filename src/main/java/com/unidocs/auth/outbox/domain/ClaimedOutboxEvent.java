package com.unidocs.auth.outbox.domain;

import java.time.Instant;
import java.util.UUID;

/** A committed event reserved by a short-lived, fenced delivery claim. */
public record ClaimedOutboxEvent(UUID id, String aggregateType, UUID aggregateId,
        long aggregateVersion, String eventType, String payload, Instant createdAt,
        int attempts, UUID claimToken) {
    @Override
    public String toString() {
        return "ClaimedOutboxEvent[id=" + id + ", payload=[REDACTED]]";
    }
}
