package com.unidocs.auth.group.persistence;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static com.unidocs.auth.group.persistence.GroupRuleRepository.*;

@Repository
public class AcademicRepository {
    public record Semester(UUID id,String code,Instant startsAt,Instant endsAt) { }
    public record Enrollment(UUID id,UUID accountId,UUID anchor,UUID semesterId,long version,UUID actor,UUID request,String fingerprint) { }
    private final JdbcTemplate jdbc;
    public AcademicRepository(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    public Optional<Semester> semester(UUID organization,UUID id) {
        if(id==null)return Optional.empty();
        return jdbc.query("SELECT * FROM academic_semester WHERE organization_id=? AND id=?",(rs,row)->new Semester(id,rs.getString("code"),
                rs.getTimestamp("starts_at").toInstant(),rs.getTimestamp("ends_at").toInstant()),bytes(organization),bytes(id)).stream().findFirst();
    }
    public Optional<Semester> semester(UUID organization,String code) {
        return jdbc.query("SELECT * FROM academic_semester WHERE organization_id=? AND code=?",(rs,row)->new Semester(uuid(rs.getBytes("id")),rs.getString("code"),
                rs.getTimestamp("starts_at").toInstant(),rs.getTimestamp("ends_at").toInstant()),bytes(organization),code).stream().findFirst();
    }
    public void createSemester(UUID organization,Semester semester) {
        jdbc.update("INSERT INTO academic_semester(id,organization_id,code,starts_at,ends_at) VALUES(?,?,?,?,?)",
                bytes(semester.id()),bytes(organization),semester.code(),time(semester.startsAt()),time(semester.endsAt()));
    }
    public List<Semester> semesters(UUID organization,UUID after,int limit) {
        return jdbc.query("SELECT * FROM academic_semester WHERE organization_id=?"+(after==null?"":" AND id>?")+" ORDER BY id LIMIT ?",
                (rs,row)->new Semester(uuid(rs.getBytes("id")),rs.getString("code"),rs.getTimestamp("starts_at").toInstant(),rs.getTimestamp("ends_at").toInstant()),
                after==null?new Object[]{bytes(organization),limit}:new Object[]{bytes(organization),bytes(after),limit});
    }
    public Optional<Enrollment> enrollment(UUID anchor) {
        return jdbc.query("SELECT * FROM student_enrollment WHERE organization_membership_id=?",(rs,row)->new Enrollment(uuid(rs.getBytes("id")),
                uuid(rs.getBytes("account_id")),anchor,uuid(rs.getBytes("semester_id")),rs.getLong("version"),uuid(rs.getBytes("updated_by")),
                uuid(rs.getBytes("last_request_id")),rs.getString("last_fingerprint")),bytes(anchor)).stream().findFirst();
    }
    public void save(UUID organization,Enrollment enrollment,Instant now) {
        jdbc.update("""
            INSERT INTO student_enrollment(id,organization_id,account_id,organization_membership_id,semester_id,version,updated_by,last_request_id,last_fingerprint,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE semester_id=VALUES(semester_id),version=VALUES(version),updated_by=VALUES(updated_by),
              last_request_id=VALUES(last_request_id),last_fingerprint=VALUES(last_fingerprint),updated_at=VALUES(updated_at)
            """,bytes(enrollment.id()),bytes(organization),bytes(enrollment.accountId()),bytes(enrollment.anchor()),bytes(enrollment.semesterId()),
                enrollment.version(),bytes(enrollment.actor()),bytes(enrollment.request()),enrollment.fingerprint(),time(now));
    }
    public List<UUID> courseMemberships(UUID organization,UUID anchor,int limit) {
        return jdbc.query("""
            SELECT gm.id FROM group_membership gm JOIN iam_group g ON g.id=gm.group_id WHERE gm.organization_id=? AND
            gm.organization_membership_id=? AND gm.status='ACTIVE' AND g.type='COURSE' ORDER BY gm.id LIMIT ?
            """,(rs,row)->uuid(rs.getBytes(1)),bytes(organization),bytes(anchor),limit);
    }
    public List<UUID> courseIds(UUID anchor,long version) {
        return jdbc.query("SELECT group_id FROM group_membership WHERE organization_membership_id=? AND source='COURSE_ENROLLMENT' AND enrollment_version=? AND status='ACTIVE' ORDER BY group_id",
                (rs,row)->uuid(rs.getBytes(1)),bytes(anchor),version);
    }
    public UUID membershipGroup(UUID id) {
        return jdbc.queryForObject("SELECT group_id FROM group_membership WHERE id=?",(rs,row)->uuid(rs.getBytes(1)),bytes(id));
    }
}
