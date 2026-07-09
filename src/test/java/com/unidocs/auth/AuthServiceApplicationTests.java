package com.unidocs.auth;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthServiceApplicationTests extends MySqlIntegrationTest {
    @Autowired Flyway flyway;
    @Autowired MockMvc mvc;

    @Test
    void flywayInitializesSchemaAndCanBeRunAgain() {
        assertThat(flyway.info().current().getVersion().getVersion()).isEqualTo("19");
        assertThat(flyway.validateWithResult().validationSuccessful).isTrue();
        assertThat(flyway.migrate().migrationsExecuted).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM flyway_schema_history WHERE success = 1", Integer.class))
                .isEqualTo(19);
        assertThat(jdbc.queryForList("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()", String.class))
                .containsExactlyInAnyOrder("flyway_schema_history", "pending_registration", "registration_verification",
                        "users", "user_profile", "user_contact", "user_preference", "user_account", "login_identity",
                        "account_group", "account_group_member", "security_audit_event",
                        "user_session", "session_account_grant", "session_refresh_token",
                        "account_credential", "session_grant_policy", "account_challenge",
                        "organization", "organization_auth_policy", "organization_membership", "outbox_event", "organization_invitation", "iam_group",
                        "organization_account_restriction","account_removal_request","account_security_notice","group_membership","group_join_request","group_rule","academic_semester","student_enrollment","group_invitation","employee_activation","institute_email_domain","institute_curator","student_admission","admission_evidence_deletion","email_password_recovery","employee_password_recovery");
        assertThat(jdbc.queryForObject("SELECT @@session.time_zone", String.class)).isIn("+00:00", "UTC");
    }

    @Test
    void anonymousHealthProbesWorkWithoutExposingDetails() throws Exception {
        for (String path : new String[]{"/actuator/health", "/actuator/health/liveness", "/actuator/health/readiness"}) {
            mvc.perform(get(path)).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("UP"))
                    .andExpect(jsonPath("$.components").doesNotExist()).andExpect(header().exists("X-Request-Id"));
        }
    }

    @Test
    void operationalAndFutureApiEndpointsRemainClosed() throws Exception {
        for (String path : new String[]{"/actuator/info", "/actuator/prometheus", "/api/v1/me"}) {
            mvc.perform(get(path)).andExpect(status().isUnauthorized())
                    .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                    .andExpect(jsonPath("$.status").value(401));
        }
    }

    @Test
    void registrationFailsClosedWhenSmtpIsNotConfigured() throws Exception {
        mvc.perform(post("/api/v1/registrations").contentType("application/json")
                .content("{\"displayName\":\"User\",\"email\":\"user@example.com\",\"password\":\"a-long-test-password\"}"))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.status").value(503));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM pending_registration", Integer.class)).isZero();
    }
}
