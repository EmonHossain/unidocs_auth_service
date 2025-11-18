package com.unidocs.auth.audit.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A verified caller's single-session logout, independent of diagnostic sampling. */
public record LogoutAuditEnvelope(UUID eventId, int schemaVersion, Instant occurredAt,
        String eventType, Outcome outcome, ReasonCode reasonCode, ActorType actorType,
        UUID actorId, TargetType targetType, UUID targetId, UUID sessionId,
        String requestId, String traceId, String sourceService, String serviceVersion) {
    public enum Outcome { SUCCESS }
    public enum ReasonCode { LOGOUT }
    public enum ActorType { ACCOUNT }
    public enum TargetType { SESSION }

    public LogoutAuditEnvelope {
        Objects.requireNonNull(eventId, "Audit event ID is required");
        Objects.requireNonNull(occurredAt, "Audit occurrence time is required");
        if (schemaVersion != 1 || !"auth-service".equals(sourceService)
                || !"auth.logout.completed".equals(eventType) || outcome != Outcome.SUCCESS
                || reasonCode != ReasonCode.LOGOUT || actorType != ActorType.ACCOUNT
                || actorId == null || sessionId == null || targetType != TargetType.SESSION
                || !sessionId.equals(targetId)) {
            throw new IllegalArgumentException("Invalid logout audit facts");
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

    public static LogoutAuditEnvelope create(UUID eventId, UUID accountId, UUID sessionId,
            Instant occurredAt, String requestId, String traceId, String serviceVersion) {
        return new LogoutAuditEnvelope(eventId, 1, occurredAt, "auth.logout.completed",
                Outcome.SUCCESS, ReasonCode.LOGOUT, ActorType.ACCOUNT, accountId,
                TargetType.SESSION, sessionId, sessionId, requestId, traceId, "auth-service", serviceVersion);
    }
}
