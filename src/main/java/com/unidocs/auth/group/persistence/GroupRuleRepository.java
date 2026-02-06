package com.unidocs.auth.group.persistence;

import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import com.unidocs.auth.group.domain.GroupRule;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Repository
public class GroupRuleRepository {
    private final JdbcTemplate jdbc;
    public GroupRuleRepository(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    public Optional<GroupRule> find(UUID organization, UUID group) {
        return jdbc.query("SELECT * FROM group_rule WHERE organization_id=? AND group_id=?",
                (rs,row)->new GroupRule(group,GroupRule.Discovery.valueOf(rs.getString("discovery_scope")),
                    GroupRule.Joining.valueOf(rs.getString("join_rule")),uuid(rs.getBytes("department_group_id")),
                    uuid(rs.getBytes("semester_id")),rs.getLong("version")),bytes(organization),bytes(group)).stream().findFirst();
    }
    public void update(UUID organization, GroupRule rule) {
        jdbc.update("UPDATE group_rule SET discovery_scope=?,join_rule=?,department_group_id=?,semester_id=?,version=version+1 WHERE organization_id=? AND group_id=?",
                rule.discovery().name(),rule.joining().name(),nullable(rule.departmentGroupId()),nullable(rule.semesterId()),bytes(organization),bytes(rule.groupId()));
    }
    public List<GroupRule> findAll(UUID organization,List<UUID> ids) {
        if(ids.isEmpty())return List.of();
        java.util.ArrayList<Object> args=new java.util.ArrayList<>();args.add(bytes(organization));ids.forEach(id->args.add(bytes(id)));
        return jdbc.query("SELECT * FROM group_rule WHERE organization_id=? AND group_id IN("+String.join(",",java.util.Collections.nCopies(ids.size(),"?"))+")",
                (rs,row)->new GroupRule(uuid(rs.getBytes("group_id")),GroupRule.Discovery.valueOf(rs.getString("discovery_scope")),
                    GroupRule.Joining.valueOf(rs.getString("join_rule")),uuid(rs.getBytes("department_group_id")),uuid(rs.getBytes("semester_id")),rs.getLong("version")),args.toArray());
    }
    public boolean university(UUID organization) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT type='UNIVERSITY' FROM organization WHERE id=?",Boolean.class,bytes(organization)));
    }
    public boolean student(UUID anchor) {
        return !jdbc.query("SELECT id FROM student_enrollment WHERE organization_membership_id=?",(rs,row)->rs.getBytes(1),bytes(anchor)).isEmpty();
    }
    // All queries use current MySQL authority; discovery never relies on cached membership metadata.
    static final String ACTIVE_TREE = """
        WITH RECURSIVE active_groups AS (
          SELECT id,organization_id,type,1 depth,CAST(IF(type='COURSE',HEX(id),'') AS CHAR(1100)) course_path
          FROM iam_group WHERE organization_id=? AND parent_group_id IS NULL AND status='ACTIVE'
          UNION ALL SELECT g.id,g.organization_id,g.type,p.depth+1,
            CONCAT_WS(',',NULLIF(p.course_path,''),IF(g.type='COURSE',HEX(g.id),NULL)) FROM iam_group g JOIN active_groups p
            ON g.organization_id=p.organization_id AND g.parent_group_id=p.id WHERE g.status='ACTIVE' AND p.depth<32
        )
        """;
    static String studentGuard(String anchorExpression) {
        return """
        NOT EXISTS(SELECT 1 FROM student_enrollment e JOIN organization o ON o.id=e.organization_id
          WHERE e.organization_membership_id=%s AND o.type='UNIVERSITY'
          AND EXISTS(SELECT 1 FROM iam_group course WHERE course.organization_id=g.organization_id AND FIND_IN_SET(HEX(course.id),g.course_path)>0
            AND NOT EXISTS(SELECT 1 FROM group_membership cm JOIN group_rule cr ON cr.group_id=cm.group_id JOIN academic_semester cs ON cs.id=cr.semester_id
              WHERE cm.group_id=course.id AND cm.organization_membership_id=e.organization_membership_id AND cm.status='ACTIVE'
                AND cm.source='COURSE_ENROLLMENT' AND cm.source_enrollment_id=e.id AND cm.enrollment_version=e.version
                AND cr.join_rule='COURSE_ENROLLMENT' AND cr.semester_id=e.semester_id AND cs.starts_at<=? AND cs.ends_at>?)))
        """.formatted(anchorExpression);
    }
    private static final String EFFECTIVE = ACTIVE_TREE + """
        SELECT gm.* FROM group_membership gm JOIN active_groups g ON g.id=gm.group_id
        WHERE gm.organization_membership_id=? AND gm.status='ACTIVE' AND gm.valid_from<=? AND (gm.valid_until IS NULL OR gm.valid_until>?)
        AND
        """ + studentGuard("gm.organization_membership_id");
    public boolean courseEligible(UUID organization,UUID group,UUID anchor,Instant now) {
        return !jdbc.query(ACTIVE_TREE+"SELECT g.id FROM active_groups g WHERE g.id=? AND "+studentGuard("?"),
                (rs,row)->rs.getBytes(1),bytes(organization),bytes(group),bytes(anchor),time(now),time(now)).isEmpty();
    }
    public boolean effective(UUID organization,UUID group,UUID anchor,Instant now,boolean manager) {
        return !jdbc.query(EFFECTIVE+" AND gm.group_id=?"+(manager?" AND gm.can_manage_group=TRUE":""),
                (rs,row)->rs.getBytes("id"),bytes(organization),bytes(anchor),time(now),time(now),time(now),time(now),bytes(group)).isEmpty();
    }
    public List<UUID> effectiveGroups(UUID organization,UUID anchor,List<UUID> ids,Instant now) {
        if(ids.isEmpty())return List.of();
        java.util.ArrayList<Object> args=new java.util.ArrayList<>(List.of(bytes(organization),bytes(anchor),time(now),time(now),time(now),time(now)));
        ids.forEach(id->args.add(bytes(id)));
        return jdbc.query(EFFECTIVE+" AND gm.group_id IN("+String.join(",",java.util.Collections.nCopies(ids.size(),"?"))+")",
                (rs,row)->uuid(rs.getBytes("group_id")),args.toArray());
    }
    public boolean discoverable(UUID organization,UUID group,UUID anchor,Instant now) {
        GroupRule rule=find(organization,group).orElse(null);
        if(rule==null || !courseEligible(organization,group,anchor,now)) return false;
        boolean studentCourse=university(organization) && student(anchor) && Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT type='COURSE' FROM iam_group WHERE id=?",Boolean.class,bytes(group)));
        if(studentCourse || rule.joining()==GroupRule.Joining.COURSE_ENROLLMENT) return effective(organization,group,anchor,now,false);
        if(effective(organization,group,anchor,now,false)) return true;
        return switch(rule.discovery()) {
            case ORGANIZATION -> true;
            case DEPARTMENT -> effective(organization,rule.departmentGroupId(),anchor,now,false);
            case INVITATION_ONLY -> !jdbc.query("SELECT id FROM group_invitation WHERE group_id=? AND organization_membership_id=? AND status='PENDING' AND expires_at>?",
                    (rs,row)->rs.getBytes(1),bytes(group),bytes(anchor),time(now)).isEmpty();
        };
    }
    public List<UUID> discoverableIds(UUID organization,UUID anchor,UUID after,int limit,Instant now) {
        // Filter before pagination: hidden rows must not shorten pages or leak existence through cursors.
        String sql=ACTIVE_TREE.substring(0,ACTIVE_TREE.lastIndexOf(')')) + """
            ), effective_members AS (
              SELECT gm.group_id FROM group_membership gm JOIN active_groups g ON g.id=gm.group_id
              WHERE gm.organization_membership_id=? AND gm.status='ACTIVE' AND gm.valid_from<=? AND (gm.valid_until IS NULL OR gm.valid_until>?)
                AND
        """+studentGuard("gm.organization_membership_id")+"""
            ) SELECT g.id FROM active_groups g JOIN group_rule r ON r.group_id=g.id JOIN organization o ON o.id=g.organization_id
            WHERE (EXISTS(SELECT 1 FROM effective_members m WHERE m.group_id=g.id) OR
              (r.join_rule<>'COURSE_ENROLLMENT' AND NOT(o.type='UNIVERSITY' AND g.type='COURSE' AND EXISTS(SELECT 1 FROM student_enrollment e WHERE e.organization_membership_id=?))
                AND (r.discovery_scope='ORGANIZATION' OR (r.discovery_scope='DEPARTMENT' AND EXISTS(SELECT 1 FROM effective_members m WHERE m.group_id=r.department_group_id))
                  OR (r.discovery_scope='INVITATION_ONLY' AND EXISTS(SELECT 1 FROM group_invitation i WHERE i.group_id=g.id AND i.organization_membership_id=? AND i.status='PENDING' AND i.expires_at>?)))))
            AND
        """+studentGuard("?");
        java.util.ArrayList<Object> args=new java.util.ArrayList<>(List.of(bytes(organization),bytes(anchor),time(now),time(now),time(now),time(now),bytes(anchor),bytes(anchor),time(now),bytes(anchor),time(now),time(now)));
        if(after!=null) { sql+=" AND g.id>?";args.add(bytes(after)); }
        sql+=" ORDER BY g.id LIMIT ?";args.add(limit);
        return jdbc.query(sql,(rs,row)->uuid(rs.getBytes(1)),args.toArray());
    }
    public static UUID uuid(byte[] value) { if(value==null)return null;ByteBuffer b=ByteBuffer.wrap(value);return new UUID(b.getLong(),b.getLong()); }
    public static byte[] nullable(UUID value) { return value==null?null:bytes(value); }
    public static Timestamp time(Instant value) { return value==null?null:Timestamp.from(value); }
}
