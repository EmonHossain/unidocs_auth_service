package com.unidocs.auth.audit.domain;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class LogoutAllAuditEnvelopeTests {
    private static final UUID EVENT = UUID.randomUUID();
    private static final UUID ACCOUNT = UUID.randomUUID();
    private static final UUID SESSION = UUID.randomUUID();
    private static final UUID GROUP = UUID.randomUUID();
    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");
    private static final String REQUEST = "01234567-89ab-cdef-0123-456789abcdef";
    private static final String TRACE = "0123456789abcdef0123456789abcdef";

    @Test
    void serializesOnlyVerifiedActorGroupActionAndSafeCorrelation() {
        JsonNode json = JsonMapper.builder().build().valueToTree(create(ACCOUNT, SESSION, GROUP, REQUEST, TRACE, "dev"));
        assertThat(json.properties().stream().map(entry -> entry.getKey()).toList()).containsExactlyInAnyOrder(
                "eventId", "schemaVersion", "occurredAt", "eventType", "outcome", "reasonCode", "actorType",
                "actorId", "targetType", "targetId", "sessionId", "requestId", "traceId", "sourceService",
                "serviceVersion", "accountGroupId");
        assertThat(json.path("schemaVersion").asInt()).isEqualTo(1);
        assertThat(json.path("eventType").asText()).isEqualTo("auth.logout.completed");
        assertThat(json.path("outcome").asText()).isEqualTo("SUCCESS");
        assertThat(json.path("reasonCode").asText()).isEqualTo("LOGOUT_ALL");
        assertThat(json.path("actorType").asText()).isEqualTo("ACCOUNT");
        assertThat(json.path("actorId").asText()).isEqualTo(ACCOUNT.toString());
        assertThat(json.path("targetType").asText()).isEqualTo("ACCOUNT_GROUP");
        assertThat(json.path("targetId").asText()).isEqualTo(GROUP.toString());
        assertThat(json.path("accountGroupId").asText()).isEqualTo(GROUP.toString());
        assertThat(json.path("sessionId").asText()).isEqualTo(SESSION.toString());
        assertThat(json.path("requestId").asText()).isEqualTo(REQUEST);
        assertThat(json.path("traceId").asText()).isEqualTo(TRACE);
        assertThat(json.path("sourceService").asText()).isEqualTo("auth-service");
    }

    @Test
    void requiresVerifiedActorRequestingSessionAndGroup() {
        assertThatIllegalArgumentException().isThrownBy(() -> create(null, SESSION, GROUP, null, null, "dev"));
        assertThatIllegalArgumentException().isThrownBy(() -> create(ACCOUNT, null, GROUP, null, null, "dev"));
        assertThatIllegalArgumentException().isThrownBy(() -> create(ACCOUNT, SESSION, null, null, null, "dev"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"secret@example.com", "01234567-89AB-cdef-0123-456789abcdef", "\r\nsecret"})
    void dropsUntrustedRequestAndTraceCorrelation(String value) {
        LogoutAllAuditEnvelope envelope = create(ACCOUNT, SESSION, GROUP, value, value, "dev");
        assertThat(envelope.requestId()).isNull();
        assertThat(envelope.traceId()).isNull();
    }

    @Test
    void dropsZeroTraceAndRejectsUnsafeVersionWithoutEchoingSecrets() {
        assertThat(create(ACCOUNT, SESSION, GROUP, null, "00000000000000000000000000000000", "dev").traceId()).isNull();
        assertThatIllegalArgumentException().isThrownBy(() -> create(ACCOUNT, SESSION, GROUP, null, null, "secret@example.com"))
                .withMessage("Invalid audit service version");
    }

    private static LogoutAllAuditEnvelope create(UUID account, UUID session, UUID group, String request, String trace, String version) {
        return LogoutAllAuditEnvelope.create(EVENT, account, session, group, NOW, request, trace, version);
    }
}

