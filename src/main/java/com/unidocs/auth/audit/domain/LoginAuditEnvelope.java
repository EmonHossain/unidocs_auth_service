package com.unidocs.auth.audit.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Versioned login audit facts; correlation fields are diagnostic, never identity proof. */
public record LoginAuditEnvelope(UUID eventId, int schemaVersion, Instant occurredAt,
        String eventType, Outcome outcome, ReasonCode reasonCode, ActorType actorType,
        UUID actorId, TargetType targetType, UUID targetId, UUID sessionId,
        String requestId, String traceId, String sourceService, String serviceVersion) {
    public enum Outcome { SUCCESS, FAILURE }
    public enum ReasonCode { AUTHENTICATED, LOGIN_REJECTED }
    public enum ActorType { ACCOUNT, UNKNOWN }
    public enum TargetType { SESSION, ACCOUNT, AUTHENTICATION }

    public LoginAuditEnvelope {
        Objects.requireNonNull(eventId, "Audit event ID is required");
        Objects.requireNonNull(occurredAt, "Audit occurrence time is required");
        if (schemaVersion != 1 || !"auth-service".equals(sourceService)) {
            throw new IllegalArgumentException("Invalid login audit envelope version or source");
        }
        if (serviceVersion == null || serviceVersion.length() > 64
                || !serviceVersion.matches("[A-Za-z0-9._+\\-]+")) {
            throw new IllegalArgumentException("Invalid audit service version");
        }
        boolean succeeded = "auth.login.succeeded".equals(eventType);
        boolean failed = "auth.login.failed".equals(eventType);
        if (succeeded) {
            if (outcome != Outcome.SUCCESS || reasonCode != ReasonCode.AUTHENTICATED
                    || actorType != ActorType.ACCOUNT || actorId == null || sessionId == null
                    || targetType != TargetType.SESSION || !sessionId.equals(targetId)) {
                throw new IllegalArgumentException("Invalid successful login audit facts");
            }
        } else if (failed) {
            if (outcome != Outcome.FAILURE || reasonCode != ReasonCode.LOGIN_REJECTED
                    || actorType != ActorType.UNKNOWN || actorId != null || sessionId != null
                    || (targetId == null ? targetType != TargetType.AUTHENTICATION : targetType != TargetType.ACCOUNT)) {
                throw new IllegalArgumentException("Invalid failed login audit facts");
            }
        } else {
            throw new IllegalArgumentException("Unsupported login audit event type");
        }
        requestId = canonicalRequestId(requestId);
        traceId = traceId != null && traceId.matches("[0-9a-f]{32}")
                && !traceId.equals("00000000000000000000000000000000") ? traceId : null;
    }

    public static LoginAuditEnvelope create(UUID eventId, UUID accountId, UUID sessionId,
            SecurityAuditEvent.Type type, Instant occurredAt, String requestId,
            String traceId, String serviceVersion) {
        if (type == SecurityAuditEvent.Type.LOGIN_SUCCEEDED) {
            return new LoginAuditEnvelope(eventId, 1, occurredAt, "auth.login.succeeded",
                    Outcome.SUCCESS, ReasonCode.AUTHENTICATED, ActorType.ACCOUNT, accountId,
                    TargetType.SESSION, sessionId, sessionId, requestId, traceId, "auth-service", serviceVersion);
        }
        if (type == SecurityAuditEvent.Type.LOGIN_FAILED) {
            return new LoginAuditEnvelope(eventId, 1, occurredAt, "auth.login.failed",
                    Outcome.FAILURE, ReasonCode.LOGIN_REJECTED, ActorType.UNKNOWN, null,
                    accountId == null ? TargetType.AUTHENTICATION : TargetType.ACCOUNT,
                    accountId, null, requestId, traceId, "auth-service", serviceVersion);
        }
        throw new IllegalArgumentException("Unsupported login audit event type");
    }

    private static String canonicalRequestId(String value) {
        if (value == null || !value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
            return null;
        }
        return value;
    }
}