package com.unidocs.auth;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.utility.TestcontainersConfiguration;

import java.net.URI;
import java.util.Map;
import java.util.Set;

@org.springframework.test.context.ActiveProfiles("test")
@org.springframework.test.context.TestPropertySource(properties={"auth.login-protection.enabled=false","auth.rate-limit.enabled=false","registration.student.maintenance-enabled=false","auth.account-lifecycle.maintenance-enabled=false","auth.account-lifecycle.notice-delay=3600000"})
@org.springframework.context.annotation.Import(TestSigningKeys.class)
public abstract class MySqlIntegrationTest {
    private static final ExternalDatabase EXTERNAL_DATABASE = ExternalDatabase.from(System.getenv());
    protected static final MySQLContainer MYSQL = EXTERNAL_DATABASE == null ? startDatabase() : null;

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        if (EXTERNAL_DATABASE != null) {
            registry.add("spring.datasource.url", EXTERNAL_DATABASE::url);
            registry.add("spring.datasource.username", EXTERNAL_DATABASE::username);
            registry.add("spring.datasource.password", EXTERNAL_DATABASE::password);
        } else {
            registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
            registry.add("spring.datasource.username", MYSQL::getUsername);
            registry.add("spring.datasource.password", MYSQL::getPassword);
        }
    }

    // This optional mode reuses Compose MySQL without starting Docker containers.
    // The allowlist protects the destructive test cleanup and Flyway setup from selecting application data.
    static final class ExternalDatabase {
        private static final Set<String> ALLOWED_OPTIONS = Set.of(
                "useSSL", "allowPublicKeyRetrieval", "connectionTimeZone", "serverTimezone",
                "forceConnectionTimeZoneToSession", "characterEncoding", "connectTimeout", "socketTimeout");
        private final String url;
        private final String username;
        private final String password;

        private ExternalDatabase(String url, String username, String password) {
            this.url = url;
            this.username = username;
            this.password = password;
        }

        static ExternalDatabase from(Map<String, String> environment) {
            String url = environment.get("AUTH_TEST_DB_URL");
            String username = environment.get("AUTH_TEST_DB_USERNAME");
            String password = environment.get("AUTH_TEST_DB_PASSWORD");
            if (url == null && username == null && password == null) {
                return null;
            }
            if (url == null || url.isBlank() || username == null || username.isBlank()
                    || password == null || password.isBlank()) {
                throw invalidConfiguration();
            }
            try {
                if (!url.startsWith("jdbc:mysql://")) {
                    throw invalidConfiguration();
                }
                URI target = URI.create(url.substring("jdbc:".length()));
                if (target.getHost() == null || target.getUserInfo() != null || target.getFragment() != null
                        || !"/auth_service_test".equals(target.getRawPath())
                        || target.getPort() == 0 || target.getPort() > 65535) {
                    throw invalidConfiguration();
                }
                String query = target.getRawQuery();
                if (query != null) {
                    for (String option : query.split("&", -1)) {
                        String[] pair = option.split("=", -1);
                        if (pair.length != 2 || !ALLOWED_OPTIONS.contains(pair[0])
                                || !pair[1].matches("[A-Za-z0-9_./:+-]+")) {
                            throw invalidConfiguration();
                        }
                    }
                }
            } catch (IllegalArgumentException invalidUrl) {
                // Never include the JDBC URL or credentials in configuration errors.
                throw invalidConfiguration();
            }
            return new ExternalDatabase(url, username, password);
        }

        private static IllegalArgumentException invalidConfiguration() {
            return new IllegalArgumentException("External integration tests require AUTH_TEST_DB_URL, "
                    + "AUTH_TEST_DB_USERNAME and AUTH_TEST_DB_PASSWORD targeting only auth_service_test "
                    + "through a single-host MySQL JDBC URL with approved connection options");
        }

        String url() { return url; }
        String username() { return username; }
        String password() { return password; }
    }

    @Autowired protected JdbcTemplate jdbc;

    private static MySQLContainer startDatabase() {
        MySQLContainer database = new MySQLContainer("mysql:8.4.8")
                .withDatabaseName("auth_service_test")
                .withLabel("com.docker.compose.project", "unidocs-auth")
                .withLabel("com.docker.compose.service", "auth-test-mysql")
                .withUrlParam("connectionTimeZone", "UTC")
                .withUrlParam("forceConnectionTimeZoneToSession", "true")
                .withStartupTimeout(java.time.Duration.ofMinutes(10))
                .withConnectTimeoutSeconds(300)
                .withReuse(TestcontainersConfiguration.getInstance().environmentSupportsReuse());
        // Manual lifecycle keeps reusable local containers alive. Ryuk cleans up CI containers.
        database.start();
        return database;
    }

    @BeforeEach
    void resetRegistrationData() {
        String currentDatabase = jdbc.queryForObject("SELECT DATABASE()", String.class);
        if (!"auth_service_test".equals(currentDatabase)) {
            throw new IllegalStateException("Destructive integration-test cleanup requires auth_service_test");
        }
        jdbc.update("DELETE FROM outbox_event");
        jdbc.update("DELETE FROM iam_developer_factor");
        jdbc.update("DELETE FROM iam_developer_eligibility");
        jdbc.update("DELETE FROM iam_controlplane_request");
        jdbc.update("DELETE FROM iam_controlplane_audit");
        jdbc.update("DELETE FROM iam_operation_restriction WHERE account_id IS NOT NULL");
        jdbc.update("DELETE FROM personal_group_audit");
        jdbc.update("DELETE FROM personal_group_invitation");
        jdbc.update("DELETE FROM personal_group_member");
        jdbc.update("DELETE FROM account_security_notice");
        jdbc.update("DELETE FROM account_removal_request");
        jdbc.update("DELETE FROM organization_account_restriction");
        jdbc.update("DELETE FROM group_membership");
        jdbc.update("DELETE FROM group_join_request");
        jdbc.update("DELETE FROM group_invitation");
        jdbc.update("DELETE FROM student_enrollment");
        jdbc.update("DELETE FROM iam_student_decision");
        jdbc.update("DELETE FROM iam_student_enforcement_proof");
        jdbc.update("DELETE FROM iam_student_report_evidence");
        jdbc.update("DELETE FROM iam_student_report");
        jdbc.update("DELETE FROM iam_study_invitation");
        jdbc.update("DELETE FROM iam_study_member");
        jdbc.update("DELETE FROM iam_study_group");
        jdbc.update("DELETE FROM iam_student_course");
        jdbc.update("DELETE FROM iam_student_admin");
        jdbc.update("DELETE FROM iam_student_state");
        jdbc.update("DELETE FROM iam_professional_assignment");
        jdbc.update("DELETE FROM iam_professional_restriction");
        jdbc.update("DELETE FROM iam_professional_reconciliation");
        jdbc.update("DELETE FROM iam_professional_notice");
        jdbc.update("DELETE FROM iam_course_offering");
        jdbc.update("DELETE FROM iam_semester_workspace");
        jdbc.update("DELETE FROM group_rule");
        jdbc.update("DELETE FROM academic_semester");
        // Immutable hierarchy: delete leaves before their parents without disabling constraints.
        while (jdbc.update("DELETE g FROM iam_group g LEFT JOIN iam_group child ON child.organization_id=g.organization_id AND child.parent_group_id=g.id WHERE child.id IS NULL") > 0) { }
        jdbc.update("DELETE FROM admission_evidence_deletion");
        jdbc.update("DELETE FROM student_admission");
        jdbc.update("DELETE FROM institute_curator");
        jdbc.update("DELETE FROM institute_email_domain");
        jdbc.update("DELETE FROM email_password_recovery");
        jdbc.update("DELETE FROM employee_password_recovery");
        jdbc.update("DELETE FROM employee_activation");
        jdbc.update("DELETE FROM organization_invitation");
        jdbc.update("DELETE FROM organization_membership");
        jdbc.update("DELETE FROM organization_auth_policy");
        jdbc.update("DELETE FROM account_challenge");
        jdbc.update("DELETE FROM account_credential");
        jdbc.update("UPDATE session_grant_policy SET idle_timeout_seconds = 1800, absolute_timeout_seconds = 43200, version = 1");
        jdbc.update("DELETE FROM session_refresh_token");
        jdbc.update("DELETE FROM session_account_grant");
        jdbc.update("DELETE FROM user_session");
        jdbc.update("DELETE FROM registration_verification");
        jdbc.update("DELETE FROM pending_registration");
        jdbc.update("DELETE FROM security_audit_event");
        jdbc.update("DELETE FROM account_group_member");
        jdbc.update("DELETE FROM user_preference");
        jdbc.update("DELETE FROM login_identity");
        jdbc.update("DELETE FROM user_contact");
        jdbc.update("DELETE FROM user_profile");
        jdbc.update("DELETE FROM account_group");
        jdbc.update("DELETE FROM user_account");
        jdbc.update("DELETE FROM organization");
        jdbc.update("DELETE FROM users");
    }
}
