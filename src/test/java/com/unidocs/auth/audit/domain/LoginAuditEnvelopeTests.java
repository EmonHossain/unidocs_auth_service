package com.unidocs.auth.audit.domain;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class LoginAuditEnvelopeTests {
    private static final UUID EVENT_ID = UUID.randomUUID();
    private static final UUID ACCOUNT_ID = UUID.randomUUID();
    private static final UUID SESSION_ID = UUID.randomUUID();
    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");
    private static final String REQUEST_ID = "01234567-89ab-cdef-0123-456789abcdef";
    private static final String TRACE_ID = "0123456789abcdef0123456789abcdef";

    @Test
    void serializesOnlyBoundedSuccessFactsAndSafeCorrelation() {
        LoginAuditEnvelope envelope = create(ACCOUNT_ID, SESSION_ID, SecurityAuditEvent.Type.LOGIN_SUCCEEDED,
                REQUEST_ID, TRACE_ID, "1.0.0+build-42");
        JsonNode json = JsonMapper.builder().build().valueToTree(envelope);
        assertThat(json.properties().stream().map(entry -> entry.getKey()).toList()).containsExactlyInAnyOrder(
                "eventId", "schemaVersion", "occurredAt", "eventType", "outcome", "reasonCode", "actorType",
                "actorId", "targetType", "targetId", "sessionId", "requestId", "traceId", "sourceService", "serviceVersion");
        assertThat(json.path("schemaVersion").asInt()).isEqualTo(1);
        assertThat(json.path("sourceService").asText()).isEqualTo("auth-service");
        assertThat(json.path("eventType").asText()).isEqualTo("auth.login.succeeded");
        assertThat(json.path("outcome").asText()).isEqualTo("SUCCESS");
        assertThat(json.path("reasonCode").asText()).isEqualTo("AUTHENTICATED");
        assertThat(json.path("actorId").asText()).isEqualTo(ACCOUNT_ID.toString());
        assertThat(json.path("targetId").asText()).isEqualTo(SESSION_ID.toString());
        assertThat(json.path("requestId").asText()).isEqualTo(REQUEST_ID);
        assertThat(json.path("traceId").asText()).isEqualTo(TRACE_ID);
    }

    @Test
    void failedLoginNeverAttributesAnAuthenticatedActorOrSession() {
        LoginAuditEnvelope known = create(ACCOUNT_ID, SESSION_ID, SecurityAuditEvent.Type.LOGIN_FAILED, null, null, "dev");
        assertThat(known.actorType()).isEqualTo(LoginAuditEnvelope.ActorType.UNKNOWN);
        assertThat(known.actorId()).isNull();
        assertThat(known.sessionId()).isNull();
        assertThat(known.targetType()).isEqualTo(LoginAuditEnvelope.TargetType.ACCOUNT);
        assertThat(known.targetId()).isEqualTo(ACCOUNT_ID);
        assertThat(known.eventType()).isEqualTo("auth.login.failed");
        assertThat(known.outcome()).isEqualTo(LoginAuditEnvelope.Outcome.FAILURE);
        assertThat(known.reasonCode()).isEqualTo(LoginAuditEnvelope.ReasonCode.LOGIN_REJECTED);
        LoginAuditEnvelope unknown = create(null, null, SecurityAuditEvent.Type.LOGIN_FAILED, null, null, "dev");
        assertThat(unknown.targetType()).isEqualTo(LoginAuditEnvelope.TargetType.AUTHENTICATION);
        assertThat(unknown.targetId()).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"secret@example.com", "01234567-89AB-cdef-0123-456789abcdef", "0123456789abcdef", "\r\nsecret"})
    void omitsInvalidRequestCorrelation(String value) {
        assertThat(create(ACCOUNT_ID, SESSION_ID, SecurityAuditEvent.Type.LOGIN_SUCCEEDED, value, TRACE_ID, "dev").requestId()).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"secret-token", "0123456789ABCDEF0123456789abcdef", "00000000000000000000000000000000", "0123456789abcdef"})
    void omitsInvalidTraceCorrelation(String value) {
        assertThat(create(ACCOUNT_ID, SESSION_ID, SecurityAuditEvent.Type.LOGIN_SUCCEEDED, REQUEST_ID, value, "dev").traceId()).isNull();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "secret@example.com", "version\r\nsecret", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
    void rejectsUnsafeDeploymentVersionWithoutEchoingItsValue(String value) {
        assertThatIllegalArgumentException().isThrownBy(() -> create(ACCOUNT_ID, SESSION_ID,
                SecurityAuditEvent.Type.LOGIN_SUCCEEDED, null, null, value)).withMessage("Invalid audit service version");
    }

    @Test
    void rejectsMissingSuccessIdentityAndUnsupportedEvents() {
        assertThatIllegalArgumentException().isThrownBy(() -> create(null, SESSION_ID,
                SecurityAuditEvent.Type.LOGIN_SUCCEEDED, null, null, "dev"));
        assertThatIllegalArgumentException().isThrownBy(() -> create(ACCOUNT_ID, null,
                SecurityAuditEvent.Type.LOGIN_SUCCEEDED, null, null, "dev"));
        assertThatIllegalArgumentException().isThrownBy(() -> create(ACCOUNT_ID, SESSION_ID,
                SecurityAuditEvent.Type.SESSION_REVOKED, null, null, "dev"));
    }

    private static LoginAuditEnvelope create(UUID accountId, UUID sessionId, SecurityAuditEvent.Type type,
            String requestId, String traceId, String version) {
        return LoginAuditEnvelope.create(EVENT_ID, accountId, sessionId, type, NOW, requestId, traceId, version);
    }
}