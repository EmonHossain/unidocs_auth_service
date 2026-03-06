package com.unidocs.auth.organization.persistence;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.*;
import java.util.ArrayList;

import jakarta.persistence.EntityManager;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import com.unidocs.auth.organization.api.OrganizationResponse;
import com.unidocs.auth.organization.domain.*;

import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Repository
public class OrganizationRepository {
    private final JdbcTemplate jdbc;
    private final EntityManager entities;
    public OrganizationRepository(JdbcTemplate jdbc, EntityManager entities) { this.jdbc=jdbc; this.entities=entities; }
    public record Creation(UUID id, String fingerprint) { }
    public boolean university(UUID organization) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM organization WHERE id=? AND type='UNIVERSITY')",Boolean.class,bytes(organization)));
    }
    public Optional<Creation> creation(UUID account, UUID request) {
        return jdbc.query("SELECT id, creation_fingerprint FROM organization WHERE created_by_account_id=? AND creation_request_id=? FOR UPDATE",
                (rs,n)->new Creation(uuid(rs.getBytes(1)),rs.getString(2)),bytes(account),bytes(request)).stream().findFirst();
    }
    public boolean instituteCurator(UUID organization,UUID membership) {
        // Legacy delegation is retained as migration data only; developer appointment is mandatory.
        return false;
    }
    public Optional<String> verifiedEmail(UUID user) {
        return jdbc.query("SELECT value FROM user_contact WHERE user_id=? AND type='EMAIL' AND verified=true AND is_primary=true LIMIT 1 FOR SHARE",
                (rs,n)->rs.getString(1),bytes(user)).stream().findFirst();
    }
    public void create(Organization organization, OrganizationAuthPolicy policy, OrganizationMembership membership) {
        entities.persist(organization); entities.flush();
        entities.persist(policy); entities.flush();
        entities.persist(membership); entities.flush();
        jdbc.update("INSERT INTO iam_student_staff_reconciliation(organization_id,membership_id) SELECT m.organization_id,m.id FROM organization_membership m JOIN organization o ON o.id=m.organization_id AND o.type='UNIVERSITY' WHERE m.id=?",bytes(membership.id()));
        jdbc.update("""
                INSERT INTO iam_professional_assignment(id,organization_id,membership_id,account_id,role_id,status,valid_from)
                SELECT UUID_TO_BIN(UUID()),m.organization_id,m.id,m.account_id,r.id,'ACTIVE',m.created_at
                FROM organization_membership m JOIN organization o ON o.id=m.organization_id AND o.type<>'UNIVERSITY'
                JOIN iam_role r ON r.role_key='ORG_ADMIN' WHERE m.id=?
                """,bytes(membership.id()));
    }
    private static final String SCOPE = """
        FROM organization o JOIN organization_membership m ON m.organization_id=o.id
        JOIN organization_auth_policy p ON p.organization_id=o.id
        JOIN user_account a ON a.id=m.account_id
        WHERE m.account_id=? AND m.status='ACTIVE' AND o.status='ACTIVE' AND a.status='ACTIVE'
        AND NOT EXISTS(SELECT 1 FROM organization_account_restriction r
            WHERE r.organization_id=o.id AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED'))
        AND p.enabled=true AND p.require_mfa=false AND p.email_domain IS NULL
        AND p.auth_method='PASSWORD' AND (? IN ('LOGIN','PASSWORD') OR (?='PIN' AND p.allow_pin_unlock=true))
        """;
    private static final String VISIBLE = "SELECT o.*, m.id membership_id, m.account_id, m.role, m.version membership_version " + SCOPE;
    public record Visibility(UUID membershipId, OrganizationMembership.Role role, long membershipVersion, long authorizationVersion) {
        public boolean matches(OrganizationResponse response, UUID account, UUID organization) {
            return response != null && account.equals(response.accountId()) && organization.equals(response.id())
                    && membershipId.equals(response.membershipId()) && role == response.role()
                    && membershipVersion == response.membershipVersion() && authorizationVersion == response.authorizationVersion();
        }
    }
    public Optional<Visibility> visibility(UUID account, String method, UUID organization) {
        return jdbc.query("SELECT m.id membership_id, m.role, m.version membership_version, o.authorization_version "
                + SCOPE + " AND o.id=? FOR SHARE", (rs,n) -> new Visibility(uuid(rs.getBytes("membership_id")),
                OrganizationMembership.Role.valueOf(rs.getString("role")),rs.getLong("membership_version"),rs.getLong("authorization_version")),
                bytes(account),method,method,bytes(organization)).stream().findFirst();
    }
    public List<OrganizationResponse> visible(UUID account, String method, UUID id, UUID after, int limit) {
        ArrayList<Object> args=new ArrayList<Object>(List.of(bytes(account),method,method));
        String sql=VISIBLE;
        if(id!=null) { sql+=" AND o.id=?"; args.add(bytes(id)); }
        if(after!=null) { sql+=" AND o.id>?"; args.add(bytes(after)); }
        sql+=" ORDER BY o.id LIMIT ? FOR SHARE"; args.add(limit);
        return jdbc.query(sql,(rs,n)->new OrganizationResponse(uuid(rs.getBytes("id")),rs.getString("name"),rs.getString("slug"),
                Organization.Type.valueOf(rs.getString("type")),uuid(rs.getBytes("membership_id")),account,
                OrganizationMembership.Role.valueOf(rs.getString("role")),rs.getLong("membership_version"),rs.getLong("authorization_version"),
                rs.getTimestamp("created_at").toInstant()),args.toArray());
    }
    public Optional<OrganizationMembership.Role> activeMembershipRole(UUID organization, UUID account) {
        return jdbc.query("SELECT role FROM organization_membership WHERE organization_id=? AND account_id=? AND status='ACTIVE' FOR UPDATE",
                (rs, row) -> OrganizationMembership.Role.valueOf(rs.getString("role")), bytes(organization), bytes(account)).stream().findFirst();
    }
    private static UUID uuid(byte[] value) { ByteBuffer b=ByteBuffer.wrap(value); return new UUID(b.getLong(),b.getLong()); }
}
