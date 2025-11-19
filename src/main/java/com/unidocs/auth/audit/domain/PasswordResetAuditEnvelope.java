package com.unidocs.auth.audit.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Verified email recovery changes a known account credential without authenticating a session. */
public record PasswordResetAuditEnvelope(UUID eventId, int schemaVersion, Instant occurredAt,
        String eventType, Outcome outcome, ReasonCode reasonCode, ActorType actorType,
        UUID actorId, TargetType targetType, UUID targetId, UUID sessionId,
        String requestId, String traceId, String sourceService, String serviceVersion) {
    public enum Outcome { SUCCESS }
    public enum ReasonCode { EMAIL_RECOVERY_VERIFIED }
    public enum ActorType { UNKNOWN }
    public enum TargetType { ACCOUNT }

    public PasswordResetAuditEnvelope {
        Objects.requireNonNull(eventId, "Audit event ID is required");
        Objects.requireNonNull(occurredAt, "Audit occurrence time is required");
        if (schemaVersion != 1 || !"auth-service".equals(sourceService)
                || !"auth.password.reset.completed".equals(eventType) || outcome != Outcome.SUCCESS
                || reasonCode != ReasonCode.EMAIL_RECOVERY_VERIFIED || actorType != ActorType.UNKNOWN
                || actorId != null || sessionId != null || targetType != TargetType.ACCOUNT
                || targetId == null) {
            throw new IllegalArgumentException("Invalid password reset audit facts");
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

    public static PasswordResetAuditEnvelope create(UUID eventId, UUID accountId,
            Instant occurredAt, String requestId, String traceId, String serviceVersion) {
        return new PasswordResetAuditEnvelope(eventId, 1, occurredAt, "auth.password.reset.completed",
                Outcome.SUCCESS, ReasonCode.EMAIL_RECOVERY_VERIFIED, ActorType.UNKNOWN, null,
                TargetType.ACCOUNT, accountId, null, requestId, traceId, "auth-service", serviceVersion);
    }
}


