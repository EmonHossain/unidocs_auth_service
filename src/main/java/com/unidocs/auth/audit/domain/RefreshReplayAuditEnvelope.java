package com.unidocs.auth.audit.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A proven refresh replay with a known session target, never an authenticated actor. */
public record RefreshReplayAuditEnvelope(UUID eventId, int schemaVersion, Instant occurredAt,
        String eventType, Outcome outcome, ReasonCode reasonCode, ActorType actorType,
        UUID actorId, TargetType targetType, UUID targetId, UUID sessionId,
        String requestId, String traceId, String sourceService, String serviceVersion) {
    public enum Outcome { FAILURE }
    public enum ReasonCode { REFRESH_REPLAY }
    public enum ActorType { UNKNOWN }
    public enum TargetType { SESSION }

    public RefreshReplayAuditEnvelope {
        Objects.requireNonNull(eventId, "Audit event ID is required");
        Objects.requireNonNull(occurredAt, "Audit occurrence time is required");
        if (schemaVersion != 1 || !"auth-service".equals(sourceService)
                || !"auth.token.refresh.failed".equals(eventType) || outcome != Outcome.FAILURE
                || reasonCode != ReasonCode.REFRESH_REPLAY || actorType != ActorType.UNKNOWN
                || actorId != null || sessionId == null || targetType != TargetType.SESSION
                || !sessionId.equals(targetId)) {
            throw new IllegalArgumentException("Invalid refresh replay audit facts");
        }
        if (serviceVersion == null || serviceVersion.length() > 64
                || !serviceVersion.matches("[A-Za-z0-9._+\\-]+")) {
            throw new IllegalArgumentException("Invalid audit service version");
        }
        requestId = requestId != null && requestId.matches(
                "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") ? requestId : null;
        traceId = traceId != null && traceId.matches("[0-9a-f]{32}")
                && !traceId.equals("00000000000000000000000000000000") ? traceId : null;
    }

    public static RefreshReplayAuditEnvelope create(UUID eventId, UUID sessionId,
            Instant occurredAt, String requestId, String traceId, String serviceVersion) {
        return new RefreshReplayAuditEnvelope(eventId, 1, occurredAt, "auth.token.refresh.failed",
                Outcome.FAILURE, ReasonCode.REFRESH_REPLAY, ActorType.UNKNOWN, null,
                TargetType.SESSION, sessionId, sessionId, requestId, traceId, "auth-service", serviceVersion);
    }
}
