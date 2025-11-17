package com.unidocs.auth.audit.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A verified caller's all-device logout for the currently authorized account group. */
public record LogoutAllAuditEnvelope(UUID eventId, int schemaVersion, Instant occurredAt,
        String eventType, Outcome outcome, ReasonCode reasonCode, ActorType actorType,
        UUID actorId, TargetType targetType, UUID targetId, UUID sessionId,
        String requestId, String traceId, String sourceService, String serviceVersion, UUID accountGroupId) {
    public enum Outcome { SUCCESS }
    public enum ReasonCode { LOGOUT_ALL }
    public enum ActorType { ACCOUNT }
    public enum TargetType { ACCOUNT_GROUP }

    public LogoutAllAuditEnvelope {
        Objects.requireNonNull(eventId, "Audit event ID is required");
        Objects.requireNonNull(occurredAt, "Audit occurrence time is required");
        if (schemaVersion != 1 || !"auth-service".equals(sourceService)
                || !"auth.logout.completed".equals(eventType) || outcome != Outcome.SUCCESS
                || reasonCode != ReasonCode.LOGOUT_ALL || actorType != ActorType.ACCOUNT
                || actorId == null || sessionId == null || targetType != TargetType.ACCOUNT_GROUP
                || accountGroupId == null || !accountGroupId.equals(targetId)) {
            throw new IllegalArgumentException("Invalid logout-all audit facts");
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

    public static LogoutAllAuditEnvelope create(UUID eventId, UUID accountId, UUID sessionId, UUID accountGroupId,
            Instant occurredAt, String requestId, String traceId, String serviceVersion) {
        return new LogoutAllAuditEnvelope(eventId, 1, occurredAt, "auth.logout.completed",
                Outcome.SUCCESS, ReasonCode.LOGOUT_ALL, ActorType.ACCOUNT, accountId,
                TargetType.ACCOUNT_GROUP, accountGroupId, sessionId, requestId, traceId, "auth-service", serviceVersion, accountGroupId);
    }
}
