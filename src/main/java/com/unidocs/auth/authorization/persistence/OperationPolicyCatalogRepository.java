package com.unidocs.auth.authorization.persistence;

import java.nio.ByteBuffer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import com.unidocs.auth.authorization.domain.AuthorityMatchMode;
import com.unidocs.auth.authorization.domain.OperationAuthorityPolicy;
import com.unidocs.auth.authorization.domain.OperationPolicySnapshot;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** A single MySQL statement supplies a coherent, bounded catalog payload, never an allow decision. */
@Repository
public class OperationPolicyCatalogRepository {
    private final JdbcTemplate jdbc;

    public OperationPolicyCatalogRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<OperationPolicySnapshot> findCurrent(String serviceId, String operationKey, String categoryKey) {
        return jdbc.query("""
                SELECT o.id operation_id, o.version operation_version, p.id policy_id, p.version policy_version,
                       p.match_mode, p.requires_scoped_authorities, b.version binding_version,
                       r.id role_id, r.version role_version, a.id authority_id,
                       a.version authority_version, a.status authority_status, ra.authority_id category_authority_id
                FROM iam_operation o
                JOIN iam_operation_policy p ON p.operation_id = o.id AND p.service_id = o.service_id
                JOIN iam_stakeholder_role_binding b ON b.category_key = ?
                JOIN iam_role r ON r.id = b.role_id
                LEFT JOIN iam_policy_authority pa ON pa.policy_id = p.id AND pa.service_id = p.service_id
                LEFT JOIN iam_authority a ON a.id = pa.authority_id AND a.service_id = pa.service_id
                LEFT JOIN iam_role_authority ra ON ra.role_id = r.id AND ra.authority_id = a.id
                WHERE o.service_id = ? AND o.operation_key = ? AND o.status = 'ACTIVE'
                  AND p.status = 'ACTIVE' AND b.status = 'ACTIVE' AND r.status = 'ACTIVE'
                ORDER BY pa.authority_slot
                LIMIT 65
                """, (ResultSet result) -> snapshot(result, serviceId, operationKey, categoryKey),
                categoryKey, serviceId, operationKey);
    }

    private static Optional<OperationPolicySnapshot> snapshot(ResultSet result, String serviceId,
            String operationKey, String categoryKey) throws SQLException {
        if (!result.next()) return Optional.empty();
        UUID operationId = uuid(result, "operation_id");
        long operationVersion = result.getLong("operation_version");
        UUID policyId = uuid(result, "policy_id");
        long policyVersion = result.getLong("policy_version");
        AuthorityMatchMode matchMode = AuthorityMatchMode.valueOf(result.getString("match_mode"));
        boolean requiresScopedAuthorities = result.getBoolean("requires_scoped_authorities");
        long bindingVersion = result.getLong("binding_version");
        UUID roleId = uuid(result, "role_id");
        long roleVersion = result.getLong("role_version");
        Set<UUID> required = new HashSet<>();
        Set<UUID> categoryAuthorities = new HashSet<>();
        Map<UUID, Long> authorityVersions = new HashMap<>();
        do {
            UUID authorityId = uuid(result, "authority_id");
            // An empty policy or even one retired requirement cannot become a partial policy.
            if (authorityId == null || !"ACTIVE".equals(result.getString("authority_status"))) return Optional.empty();
            required.add(authorityId);
            if (required.size() > OperationAuthorityPolicy.MAX_REQUIRED_AUTHORITIES) return Optional.empty();
            authorityVersions.put(authorityId, result.getLong("authority_version"));
            if (result.getBytes("category_authority_id") != null) categoryAuthorities.add(authorityId);
        } while (result.next());
        return Optional.of(new OperationPolicySnapshot(operationId, serviceId, operationKey, operationVersion,
                policyId, policyVersion, categoryKey, bindingVersion, roleId, roleVersion,
                new OperationAuthorityPolicy(required, matchMode, requiresScopedAuthorities),
                categoryAuthorities, authorityVersions));
    }

    private static UUID uuid(ResultSet result, String column) throws SQLException {
        byte[] value = result.getBytes(column);
        if (value == null) return null;
        ByteBuffer buffer = ByteBuffer.wrap(value);
        return new UUID(buffer.getLong(), buffer.getLong());
    }
}
