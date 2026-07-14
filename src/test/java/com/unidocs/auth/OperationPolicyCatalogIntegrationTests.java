package com.unidocs.auth;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;

import com.unidocs.auth.authorization.application.OperationPolicyCatalogService;
import com.unidocs.auth.authorization.domain.AuthorityMatchMode;
import com.unidocs.auth.authorization.domain.OperationAuthorityEvidence;
import com.unidocs.auth.authorization.domain.OperationPolicySnapshot;
import com.unidocs.auth.authorization.persistence.OperationPolicyCatalogRepository;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.UncategorizedSQLException;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Transactional;

import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;

@SpringJUnitConfig(OperationPolicyCatalogIntegrationTests.CatalogConfiguration.class)
@Transactional
class OperationPolicyCatalogIntegrationTests extends MySqlIntegrationTest {
    @Autowired OperationPolicyCatalogService catalog;
    private UUID roleId;
    private UUID operationId;
    private UUID policyId;
    private UUID authorityId;
    private String operationKey;

    // The catalog tests roll back their own fixtures and never clear identity/application data.
    @Override
    @BeforeEach
    void resetRegistrationData() {
        assertThat(jdbc.queryForObject("SELECT DATABASE()", String.class)).isEqualTo("auth_service_test");
    }

    @BeforeEach
    void createCatalog() {
        jdbc.update("DELETE FROM iam_stakeholder_role_binding WHERE category_key='INDIVIDUAL'");
        roleId = UUID.randomUUID();
        operationId = UUID.randomUUID();
        policyId = UUID.randomUUID();
        authorityId = UUID.randomUUID();
        operationKey = "file.share." + operationId.toString();
        jdbc.update("INSERT INTO iam_authority VALUES (?, 'document-service', ?, 'ACTIVE', 7, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))",
                bytes(authorityId), operationKey);
        jdbc.update("INSERT INTO iam_operation VALUES (?, 'document-service', ?, 'ACTIVE', 3, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))",
                bytes(operationId), operationKey);
        jdbc.update("INSERT INTO iam_role VALUES (?, ?, 'ACTIVE', 5, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))",
                bytes(roleId), "BASIC_" + roleId);
        jdbc.update("INSERT INTO iam_role_authority VALUES (?, ?)", bytes(roleId), bytes(authorityId));
        jdbc.update("INSERT INTO iam_stakeholder_role_binding VALUES ('INDIVIDUAL', ?, 'ACTIVE', 11, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))",
                bytes(roleId));
        jdbc.update("INSERT INTO iam_operation_policy VALUES (?, ?, 'document-service', 'ALL_OF', TRUE, 'ACTIVE', 13, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))",
                bytes(policyId), bytes(operationId));
        jdbc.update("INSERT INTO iam_policy_authority VALUES (?, 'document-service', ?, 1)", bytes(policyId), bytes(authorityId));
    }

    @Test
    void readsExactPolicyAndDependencyRevisions() {
        OperationPolicySnapshot snapshot = load();
        assertThat(snapshot.operationId()).isEqualTo(operationId);
        assertThat(snapshot.policyId()).isEqualTo(policyId);
        assertThat(snapshot.categoryRoleId()).isEqualTo(roleId);
        assertThat(snapshot.operationVersion()).isEqualTo(3);
        assertThat(snapshot.policyVersion()).isEqualTo(13);
        assertThat(snapshot.categoryBindingVersion()).isEqualTo(11);
        assertThat(snapshot.categoryRoleVersion()).isEqualTo(5);
        assertThat(snapshot.authorityVersions()).isEqualTo(Map.of(authorityId, 7L));
        assertThat(snapshot.categoryAuthorityIds()).containsExactly(authorityId);
        assertThat(snapshot.policy().matchMode()).isEqualTo(AuthorityMatchMode.ALL_OF);
        assertThat(snapshot.policy().requiresScopedAuthorities()).isTrue();
        assertThat(snapshot.policy().matches(evidence(snapshot, Set.of(authorityId)))).isTrue();
        assertThat(catalog.load("another-service", operationKey, "INDIVIDUAL")).isEmpty();
        assertThat(catalog.load("document-service", operationKey, "ORGANIZATION")).isEmpty();
        assertThat(catalog.load("document-service", "unknown.operation", "INDIVIDUAL")).isEmpty();
    }

    @Test
    void nextReadObservesCapabilityRemovalAndVersionWithoutKafkaOrRelogin() {
        OperationPolicySnapshot before = load();
        assertThat(before.policy().matches(evidence(before, Set.of(authorityId)))).isTrue();
        jdbc.update("DELETE FROM iam_role_authority WHERE role_id = ? AND authority_id = ?", bytes(roleId), bytes(authorityId));
        jdbc.update("UPDATE iam_role SET version = version + 1 WHERE id = ?", bytes(roleId));
        OperationPolicySnapshot after = load();
        assertThat(after.categoryRoleVersion()).isEqualTo(6);
        assertThat(after.categoryAuthorityIds()).isEmpty();
        assertThat(after.policy().matches(evidence(after, Set.of(authorityId)))).isFalse();
    }

    @Test
    void anyOfCannotMixDifferentAuthoritiesAcrossCategoryAndLocalScope() {
        UUID alternative = addAuthority("file.alternative." + UUID.randomUUID(), "document-service");
        jdbc.update("INSERT INTO iam_policy_authority VALUES (?, 'document-service', ?, 2)", bytes(policyId), bytes(alternative));
        jdbc.update("UPDATE iam_operation_policy SET match_mode = 'ANY_OF', version = version + 1 WHERE id = ?", bytes(policyId));
        OperationPolicySnapshot snapshot = load();
        assertThat(snapshot.policy().matches(evidence(snapshot, Set.of(alternative)))).isFalse();
        assertThat(snapshot.policy().matches(evidence(snapshot, Set.of(authorityId)))).isTrue();
        jdbc.update("UPDATE iam_authority SET status = 'RETIRED', version = version + 1 WHERE id = ?", bytes(alternative));
        assertThat(catalog.load("document-service", operationKey, "INDIVIDUAL")).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"iam_operation", "iam_operation_policy", "iam_role", "iam_stakeholder_role_binding", "iam_authority"})
    void retiredOrDisabledDependenciesFailClosed(String table) {
        String status = table.equals("iam_operation") || table.equals("iam_authority") ? "RETIRED" : "DISABLED";
        // Only service-owned table names from this fixed test matrix enter SQL.
        if (table.equals("iam_stakeholder_role_binding")) {
            jdbc.update("UPDATE iam_stakeholder_role_binding SET status = ?, version = version + 1 WHERE category_key = 'INDIVIDUAL'", status);
        } else {
            UUID target = switch (table) {
                case "iam_operation" -> operationId;
                case "iam_operation_policy" -> policyId;
                case "iam_role" -> roleId;
                case "iam_authority" -> authorityId;
                default -> throw new IllegalArgumentException("Unknown test table");
            };
            jdbc.update("UPDATE " + table + " SET status = ?, version = version + 1 WHERE id = ?", status, bytes(target));
        }
        assertThat(catalog.load("document-service", operationKey, "INDIVIDUAL")).isEmpty();
    }

    @Test
    void anEmptyPolicyIsNeverAnAllowAllPolicy() {
        jdbc.update("DELETE FROM iam_policy_authority WHERE policy_id = ?", bytes(policyId));
        assertThat(catalog.load("document-service", operationKey, "INDIVIDUAL")).isEmpty();
    }

    @Test
    void schemaRejectsDuplicateOrCrossServiceRequirementsAndInvalidRevisions() {
        assertThatThrownBy(() -> addAuthority(operationKey, "document-service")).isInstanceOf(DataIntegrityViolationException.class);
        UUID other = addAuthority("other.permission." + UUID.randomUUID(), "another-service");
        assertThatThrownBy(() -> jdbc.update("INSERT INTO iam_policy_authority VALUES (?, 'document-service', ?, 2)",
                bytes(policyId), bytes(other))).isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> jdbc.update("UPDATE iam_role SET version = 0 WHERE id = ?", bytes(roleId)))
                .isInstanceOfSatisfying(UncategorizedSQLException.class,
                        exception -> assertThat(exception.getSQLException().getErrorCode()).isEqualTo(3819));
        assertThatThrownBy(() -> jdbc.update("INSERT INTO iam_stakeholder_role_binding VALUES ('INDIVIDUAL', ?, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))",
                bytes(roleId))).isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void schemaBoundsRequirementsToSixtyFourUniqueSlots() {
        UUID other = addAuthority("other.permission." + UUID.randomUUID(), "document-service");
        assertThatThrownBy(() -> jdbc.update("INSERT INTO iam_policy_authority VALUES (?, 'document-service', ?, 65)",
                bytes(policyId), bytes(other))).isInstanceOfSatisfying(UncategorizedSQLException.class,
                        exception -> assertThat(exception.getSQLException().getErrorCode()).isEqualTo(3819));
        assertThatThrownBy(() -> jdbc.update("INSERT INTO iam_policy_authority VALUES (?, 'document-service', ?, 1)",
                bytes(policyId), bytes(other))).isInstanceOf(DataIntegrityViolationException.class);
    }

    private UUID addAuthority(String key, String serviceId) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO iam_authority VALUES (?, ?, ?, 'ACTIVE', 1, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))", bytes(id), serviceId, key);
        return id;
    }

    private OperationPolicySnapshot load() {
        return catalog.load("document-service", operationKey, "INDIVIDUAL").orElseThrow();
    }

    private static OperationAuthorityEvidence evidence(OperationPolicySnapshot snapshot, Set<UUID> scoped) {
        return new OperationAuthorityEvidence(snapshot.categoryAuthorityIds(), scoped, true, false);
    }

    @Configuration(proxyBeanMethods = false)
    @EnableTransactionManagement
    @Import({OperationPolicyCatalogService.class, OperationPolicyCatalogRepository.class})
    static class CatalogConfiguration {
        @Bean
        DataSource dataSource(Environment environment) {
            return new DriverManagerDataSource(environment.getRequiredProperty("spring.datasource.url"),
                    environment.getRequiredProperty("spring.datasource.username"), environment.getRequiredProperty("spring.datasource.password"));
        }

        @Bean(initMethod = "migrate")
        Flyway flyway(DataSource dataSource) {
            return Flyway.configure().dataSource(dataSource).cleanDisabled(true).load();
        }

        @Bean
        @DependsOn("flyway")
        JdbcTemplate jdbcTemplate(DataSource dataSource) { return new JdbcTemplate(dataSource); }

        @Bean
        PlatformTransactionManager transactionManager(DataSource dataSource) { return new DataSourceTransactionManager(dataSource); }
    }
}
