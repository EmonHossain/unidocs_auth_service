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
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class PasswordResetAuditEnvelopeTests {
    private static final UUID EVENT_ID = UUID.randomUUID();
    private static final UUID ACCOUNT_ID = UUID.randomUUID();
    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");
    private static final String REQUEST_ID = "01234567-89ab-cdef-0123-456789abcdef";
    private static final String TRACE_ID = "0123456789abcdef0123456789abcdef";

    @Test
    void serializesOnlyRecoveryFactsWithoutClaimingAuthenticatedActorOrSession() {
        PasswordResetAuditEnvelope envelope = create(REQUEST_ID, TRACE_ID, "1.0.0+build-42");
        JsonNode json = JsonMapper.builder().build().valueToTree(envelope);
        assertThat(json.properties().stream().map(entry -> entry.getKey()).toList()).containsExactlyInAnyOrder(
                "eventId", "schemaVersion", "occurredAt", "eventType", "outcome", "reasonCode", "actorType",
                "actorId", "targetType", "targetId", "sessionId", "requestId", "traceId", "sourceService", "serviceVersion");
        assertThat(json.path("eventId").asText()).isEqualTo(EVENT_ID.toString());
        assertThat(json.path("schemaVersion").asInt()).isEqualTo(1);
        assertThat(json.path("eventType").asText()).isEqualTo("auth.password.reset.completed");
        assertThat(json.path("outcome").asText()).isEqualTo("SUCCESS");
        assertThat(json.path("reasonCode").asText()).isEqualTo("EMAIL_RECOVERY_VERIFIED");
        assertThat(json.path("actorType").asText()).isEqualTo("UNKNOWN");
        assertThat(json.path("actorId").isNull()).isTrue();
        assertThat(json.path("targetType").asText()).isEqualTo("ACCOUNT");
        assertThat(json.path("targetId").asText()).isEqualTo(ACCOUNT_ID.toString());
        assertThat(json.path("sessionId").isNull()).isTrue();
        assertThat(json.path("requestId").asText()).isEqualTo(REQUEST_ID);
        assertThat(json.path("traceId").asText()).isEqualTo(TRACE_ID);
        assertThat(json.path("sourceService").asText()).isEqualTo("auth-service");
        assertThat(json.path("serviceVersion").asText()).isEqualTo("1.0.0+build-42");
        assertThat(envelope.occurredAt()).isEqualTo(NOW);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"secret@example.com", "01234567-89AB-cdef-0123-456789abcdef", "0123456789abcdef", "\r\nsecret"})
    void omitsUnsafeRequestCorrelation(String value) {
        assertThat(create(value, TRACE_ID, "dev").requestId()).isNull();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"secret-token", "0123456789ABCDEF0123456789abcdef", "00000000000000000000000000000000", "0123456789abcdef"})
    void omitsUnsafeTraceCorrelation(String value) {
        assertThat(create(REQUEST_ID, value, "dev").traceId()).isNull();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "secret@example.com", "version\r\nsecret", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
    void rejectsUnsafeVersionWithoutEchoingInput(String value) {
        assertThatIllegalArgumentException().isThrownBy(() -> create(null, null, value))
                .withMessage("Invalid audit service version");
    }

    @Test
    void requiresEventIdentityTimeAndTargetAccount() {
        assertThatNullPointerException().isThrownBy(() -> PasswordResetAuditEnvelope.create(
                null, ACCOUNT_ID, NOW, null, null, "dev"));
        assertThatNullPointerException().isThrownBy(() -> PasswordResetAuditEnvelope.create(
                EVENT_ID, ACCOUNT_ID, null, null, null, "dev"));
        assertThatIllegalArgumentException().isThrownBy(() -> PasswordResetAuditEnvelope.create(
                EVENT_ID, null, NOW, null, null, "dev"));
    }

    @Test
    void directConstructionCannotInventAnActorSessionOrDifferentEvent() {
        assertInvalidFacts(1, "auth.password.reset.completed", ACCOUNT_ID, null, "auth-service");
        assertInvalidFacts(1, "auth.password.reset.completed", null, UUID.randomUUID(), "auth-service");
        assertInvalidFacts(2, "auth.password.reset.completed", null, null, "auth-service");
        assertInvalidFacts(1, "auth.login.succeeded", null, null, "auth-service");
        assertInvalidFacts(1, "auth.password.reset.completed", null, null, "other-service");
    }

    private static void assertInvalidFacts(int schemaVersion, String eventType, UUID actorId,
            UUID sessionId, String sourceService) {
        assertThatIllegalArgumentException().isThrownBy(() -> new PasswordResetAuditEnvelope(
                EVENT_ID, schemaVersion, NOW, eventType, PasswordResetAuditEnvelope.Outcome.SUCCESS,
                PasswordResetAuditEnvelope.ReasonCode.EMAIL_RECOVERY_VERIFIED,
                PasswordResetAuditEnvelope.ActorType.UNKNOWN, actorId,
                PasswordResetAuditEnvelope.TargetType.ACCOUNT, ACCOUNT_ID, sessionId,
                null, null, sourceService, "dev"));
    }

    private static PasswordResetAuditEnvelope create(String requestId, String traceId, String version) {
        return PasswordResetAuditEnvelope.create(EVENT_ID, ACCOUNT_ID, NOW, requestId, traceId, version);
    }
}
