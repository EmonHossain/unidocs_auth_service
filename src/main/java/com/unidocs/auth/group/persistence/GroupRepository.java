package com.unidocs.auth.group.persistence;

import java.nio.ByteBuffer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import jakarta.persistence.EntityManager;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import com.unidocs.auth.group.api.GroupResponse;
import com.unidocs.auth.group.domain.Group;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Repository
public class GroupRepository {
    public record Creation(UUID id, String fingerprint) { }
    public record Visible(GroupResponse group, int depth) { }
    private final JdbcTemplate jdbc;
    private final EntityManager entities;

    public GroupRepository(JdbcTemplate jdbc, EntityManager entities) {
        this.jdbc = jdbc;
        this.entities = entities;
    }

    // Group mutations serialize on the organization root. Reads retain a shared root lock.
    public boolean lockOrganization(UUID organization, boolean mutation) {
        return !jdbc.query("SELECT id FROM organization WHERE id=? " + (mutation ? "FOR UPDATE" : "FOR SHARE"),
                (rs, row) -> rs.getBytes(1), bytes(organization)).isEmpty();
    }

    public Optional<Creation> creation(UUID organization, UUID account, UUID request) {
        return jdbc.query("""
                SELECT id, creation_fingerprint FROM iam_group
                WHERE organization_id=? AND created_by_account_id=? AND creation_request_id=?
                """, (rs, row) -> new Creation(uuid(rs.getBytes(1)), rs.getString(2)),
                bytes(organization), bytes(account), bytes(request)).stream().findFirst();
    }

    public void create(Group group) {
        entities.persist(group); entities.flush();
        jdbc.update("""
            INSERT INTO group_rule(group_id,organization_id,discovery_scope,join_rule,version)
            SELECT g.id,g.organization_id,'ORGANIZATION',IF(o.type='UNIVERSITY' AND g.type='COURSE','COURSE_ENROLLMENT','APPROVAL'),1
            FROM iam_group g JOIN organization o ON o.id=g.organization_id WHERE g.id=?
            """, bytes(group.id()));
    }

    private static final String VISIBLE = """
            WITH RECURSIVE visible_groups AS (
                SELECT g.*, 1 AS depth FROM iam_group g
                WHERE g.organization_id=? AND g.parent_group_id IS NULL AND g.status='ACTIVE'
                UNION ALL
                SELECT g.*, p.depth+1 FROM iam_group g JOIN visible_groups p
                  ON g.organization_id=p.organization_id AND g.parent_group_id=p.id
                WHERE g.status='ACTIVE' AND p.depth<32
            )
            SELECT * FROM visible_groups
            """;

    public Optional<Visible> find(UUID organization, UUID id) {
        return jdbc.query(VISIBLE + " WHERE id=?", (rs, row) -> new Visible(response(rs), rs.getInt("depth")),
                bytes(organization), bytes(id)).stream().findFirst();
    }

    public List<GroupResponse> list(UUID organization, UUID after, int limit) {
        return jdbc.query(VISIBLE + (after == null ? "" : " WHERE id>?") + " ORDER BY id LIMIT ?",
                (rs, row) -> response(rs), after == null ? new Object[]{bytes(organization), limit}
                        : new Object[]{bytes(organization), bytes(after), limit});
    }

    public List<GroupResponse> findAll(UUID organization,List<UUID> ids) {
        if(ids.isEmpty())return List.of();
        java.util.ArrayList<Object> args=new java.util.ArrayList<>();args.add(bytes(organization));
        ids.forEach(id->args.add(bytes(id)));
        return jdbc.query(VISIBLE+" WHERE id IN("+String.join(",",java.util.Collections.nCopies(ids.size(),"?"))+")",
                (rs,row)->response(rs),args.toArray());
    }

    private static GroupResponse response(ResultSet rs) throws SQLException {
        return new GroupResponse(uuid(rs.getBytes("id")), uuid(rs.getBytes("organization_id")),
                uuid(rs.getBytes("parent_group_id")), rs.getString("name"),
                Group.Type.valueOf(rs.getString("type")), Group.Status.valueOf(rs.getString("status")),
                rs.getLong("version"), rs.getTimestamp("created_at").toInstant(), rs.getTimestamp("updated_at").toInstant());
    }
    private static UUID uuid(byte[] value) {
        if (value == null) return null;
        ByteBuffer buffer = ByteBuffer.wrap(value);
        return new UUID(buffer.getLong(), buffer.getLong());
    }
}
