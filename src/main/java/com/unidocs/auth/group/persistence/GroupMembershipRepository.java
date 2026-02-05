package com.unidocs.auth.group.persistence;

import java.nio.ByteBuffer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import com.unidocs.auth.group.domain.GroupMembership;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Repository
public class GroupMembershipRepository {
    public record Assignment(GroupMembership membership, String fingerprint) { }
    public record Row(GroupMembership membership, boolean organizationAvailable) { }
    private final JdbcTemplate jdbc;
    public GroupMembershipRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public Optional<UUID> accountGroup(UUID account) {
        return jdbc.query("SELECT g.id FROM account_group g JOIN user_account a ON a.user_id=g.user_id WHERE a.id=?",
                (rs, row) -> uuid(rs.getBytes(1)), bytes(account)).stream().findFirst();
    }
    public Optional<UUID> memberAccount(UUID organization, UUID group, UUID membership) {
        return jdbc.query("SELECT account_id FROM group_membership WHERE organization_id=? AND group_id=? AND id=?",
                (rs, row) -> uuid(rs.getBytes(1)), bytes(organization), bytes(group), bytes(membership)).stream().findFirst();
    }
    public Optional<Assignment> assignment(UUID organization, UUID actor, UUID request) {
        return jdbc.query("SELECT * FROM group_membership WHERE organization_id=? AND assigned_by_account_id=? AND assignment_request_id=?",
                (rs, row) -> new Assignment(map(rs), rs.getString("assignment_fingerprint")),
                bytes(organization), bytes(actor), bytes(request)).stream().findFirst();
    }
    public Optional<GroupMembership> find(UUID organization, UUID group, UUID membership) {
        return jdbc.query("SELECT * FROM group_membership WHERE organization_id=? AND group_id=? AND id=?",
                (rs, row) -> map(rs), bytes(organization), bytes(group), bytes(membership)).stream().findFirst();
    }
    public void create(GroupMembership membership, UUID actor, UUID request, String fingerprint) {
        create(membership,actor,request,fingerprint,null);
    }
    public void create(GroupMembership membership, UUID actor, UUID request, String fingerprint, Long enrollmentVersion) {
        jdbc.update("""
            INSERT INTO group_membership(id,organization_id,group_id,account_id,organization_membership_id,role,
                membership_type,source,status,valid_from,valid_until,version,assigned_by_account_id,
                assignment_request_id,assignment_fingerprint,created_at,updated_at,source_request_id,can_manage_group,source_enrollment_id,enrollment_version,source_invitation_id)
            VALUES(?,?,?,?,?,?,?,?,'ACTIVE',?,?,1,?,?,?,?,?,?,?,?,?,?)
            """, bytes(membership.id()), bytes(membership.organizationId()), bytes(membership.groupId()),
                bytes(membership.accountId()), bytes(membership.organizationMembershipId()), membership.role(),
                membership.membershipType().name(), membership.source().name(), time(membership.validFrom()),
                time(membership.validUntil()), bytes(actor), bytes(request), fingerprint,
                time(membership.createdAt()), time(membership.updatedAt()), source(membership,GroupMembership.Source.ADMIN_APPROVAL), membership.canManageGroup(),
                source(membership,GroupMembership.Source.COURSE_ENROLLMENT),enrollmentVersion,source(membership,GroupMembership.Source.INVITATION));
    }
    public void revoke(UUID id, UUID actor, Instant now) {
        jdbc.update("UPDATE group_membership SET status='REVOKED',version=version+1,revoked_at=?,revoked_by_account_id=?,updated_at=? WHERE id=? AND status='ACTIVE'",
                time(now), bytes(actor), time(now), bytes(id));
    }
    public long advanceOrganization(UUID organization, Instant now) {
        jdbc.update("UPDATE organization SET authorization_version=authorization_version+1,updated_at=? WHERE id=?", time(now), bytes(organization));
        return jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?", Long.class, bytes(organization));
    }
    private static final String VISIBLE_GROUPS = GroupRuleRepository.ACTIVE_TREE + """
        SELECT gm.*, (m.status='ACTIVE' AND a.status='ACTIVE' AND NOT EXISTS(
            SELECT 1 FROM organization_account_restriction r WHERE r.organization_id=gm.organization_id
                AND r.user_id=a.user_id AND r.status IN('REMOVED','BLACKLISTED')) AND
        """ + GroupRuleRepository.studentGuard("gm.organization_membership_id") + """
        ) AS organization_available
        FROM group_membership gm JOIN active_groups g ON g.id=gm.group_id AND g.organization_id=gm.organization_id
        JOIN organization_membership m ON m.id=gm.organization_membership_id AND m.organization_id=gm.organization_id AND m.account_id=gm.account_id
        JOIN user_account a ON a.id=gm.account_id
        WHERE gm.organization_id=?
        """;
    public List<Row> list(UUID organization, UUID group, UUID organizationMembership, UUID after, int limit, Instant now) {
        List<Object> args = new ArrayList<>(List.of(bytes(organization), time(now), time(now), bytes(organization)));
        String sql = VISIBLE_GROUPS;
        if (group != null) { sql += " AND gm.group_id=?"; args.add(bytes(group)); }
        if (organizationMembership != null) {
            sql += " AND "+GroupRuleRepository.studentGuard("gm.organization_membership_id");
            args.add(time(now));args.add(time(now));
            sql += " AND gm.organization_membership_id=? AND gm.status='ACTIVE' AND gm.valid_from<=? AND (gm.valid_until IS NULL OR gm.valid_until>?)";
            args.add(bytes(organizationMembership)); args.add(time(now)); args.add(time(now));
        }
        if (after != null) { sql += " AND gm.id>?"; args.add(bytes(after)); }
        sql += " ORDER BY gm.id LIMIT ?"; args.add(limit);
        return jdbc.query(sql, (rs, row) -> new Row(map(rs), rs.getBoolean("organization_available")), args.toArray());
    }
    private static GroupMembership map(ResultSet rs) throws SQLException {
        return new GroupMembership(uuid(rs.getBytes("id")), uuid(rs.getBytes("organization_id")), uuid(rs.getBytes("group_id")),
                uuid(rs.getBytes("account_id")), uuid(rs.getBytes("organization_membership_id")), rs.getString("role"),
                GroupMembership.MembershipType.valueOf(rs.getString("membership_type")), GroupMembership.Source.valueOf(rs.getString("source")),
                reference(rs),
                GroupMembership.Status.valueOf(rs.getString("status")), rs.getTimestamp("valid_from").toInstant(),
                rs.getTimestamp("valid_until") == null ? null : rs.getTimestamp("valid_until").toInstant(),
                rs.getLong("version"), rs.getTimestamp("created_at").toInstant(), rs.getTimestamp("updated_at").toInstant(),rs.getBoolean("can_manage_group"));
    }
    private static byte[] source(GroupMembership m,GroupMembership.Source source) { return m.source()==source?bytes(UUID.fromString(m.sourceReference())):null; }
    private static String reference(ResultSet rs) throws SQLException {
        for(String column:List.of("source_request_id","source_enrollment_id","source_invitation_id")) {
            byte[] value=rs.getBytes(column);if(value!=null)return uuid(value).toString();
        }
        return null;
    }
    private static Timestamp time(Instant value) { return value == null ? null : Timestamp.from(value); }
    public boolean hasActiveAssignment(UUID group, UUID anchor) {
        return !jdbc.query("SELECT id FROM group_membership WHERE group_id=? AND organization_membership_id=? AND status='ACTIVE'",
                (rs,row)->rs.getBytes(1),bytes(group),bytes(anchor)).isEmpty();
    }
    private static UUID uuid(byte[] value) { ByteBuffer buffer = ByteBuffer.wrap(value); return new UUID(buffer.getLong(), buffer.getLong()); }
}
