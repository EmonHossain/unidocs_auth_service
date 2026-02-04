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
import com.unidocs.auth.group.domain.GroupJoinRequest;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Repository
public class GroupJoinRepository {
    public record Stored(GroupJoinRequest request, String creationFingerprint, String reviewFingerprint) { }
    private final JdbcTemplate jdbc;
    public GroupJoinRepository(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    public Optional<Stored> find(UUID organization, UUID group, UUID id) {
        return jdbc.query("SELECT * FROM group_join_request WHERE organization_id=? AND group_id=? AND id=?",
                (rs,row)->stored(rs),bytes(organization),bytes(group),bytes(id)).stream().findFirst();
    }
    public Optional<Stored> retry(UUID organization, UUID account, UUID request) {
        return jdbc.query("SELECT * FROM group_join_request WHERE organization_id=? AND account_id=? AND creation_request_id=?",
                (rs,row)->stored(rs),bytes(organization),bytes(account),bytes(request)).stream().findFirst();
    }
    public void create(UUID id, UUID organization, UUID group, UUID account, UUID anchor, UUID request, String fingerprint,
            String role, String reason, Instant now) {
        jdbc.update("""
            INSERT INTO group_join_request(id,organization_id,group_id,account_id,organization_membership_id,creation_request_id,
              creation_fingerprint,requested_role,reason,status,version,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,'PENDING',1,?,?)
            """,bytes(id),bytes(organization),bytes(group),bytes(account),bytes(anchor),bytes(request),fingerprint,role,reason,time(now),time(now));
    }
    public void review(UUID id, boolean approve, UUID actor, String reason, String fingerprint, UUID membership, Instant now) {
        jdbc.update("""
            UPDATE group_join_request SET status=?,version=version+1,reviewed_by_account_id=?,reviewed_at=?,review_reason=?,
              review_fingerprint=?,approved_membership_id=?,updated_at=? WHERE id=? AND status='PENDING'
            """,approve?"APPROVED":"REJECTED",bytes(actor),time(now),reason,fingerprint,membership==null?null:bytes(membership),time(now),bytes(id));
    }
    public void cancel(UUID id, Instant now) {
        jdbc.update("UPDATE group_join_request SET status='CANCELLED',version=version+1,updated_at=? WHERE id=? AND status='PENDING'",time(now),bytes(id));
    }
    public List<GroupJoinRequest> list(UUID organization, UUID group, UUID account, UUID anchor, GroupJoinRequest.Status status, UUID after, int limit) {
        String sql="SELECT * FROM group_join_request WHERE organization_id=?";
        List<Object> args=new ArrayList<>(List.of(bytes(organization)));
        if(group!=null) { sql+=" AND group_id=?";args.add(bytes(group)); }
        if(account!=null) { sql+=" AND account_id=? AND organization_membership_id=?";args.add(bytes(account));args.add(bytes(anchor)); }
        if(status!=null) { sql+=" AND status=?";args.add(status.name()); }
        if(after!=null) { sql+=" AND id>?";args.add(bytes(after)); }
        sql+=" ORDER BY id LIMIT ?";args.add(limit);
        return jdbc.query(sql,(rs,row)->stored(rs).request(),args.toArray());
    }
    private static Stored stored(ResultSet rs) throws SQLException {
        return new Stored(new GroupJoinRequest(id(rs,"id"),id(rs,"organization_id"),id(rs,"group_id"),id(rs,"account_id"),id(rs,"organization_membership_id"),
                rs.getString("requested_role"),rs.getString("reason"),GroupJoinRequest.Status.valueOf(rs.getString("status")),rs.getLong("version"),
                id(rs,"reviewed_by_account_id"),instant(rs,"reviewed_at"),rs.getString("review_reason"),id(rs,"approved_membership_id"),
                instant(rs,"created_at"),instant(rs,"updated_at")),rs.getString("creation_fingerprint"),rs.getString("review_fingerprint"));
    }
    private static Timestamp time(Instant value) { return Timestamp.from(value); }
    private static Instant instant(ResultSet rs,String name) throws SQLException { Timestamp value=rs.getTimestamp(name);return value==null?null:value.toInstant(); }
    private static UUID id(ResultSet rs,String name) throws SQLException { byte[] value=rs.getBytes(name);if(value==null)return null;ByteBuffer buffer=ByteBuffer.wrap(value);return new UUID(buffer.getLong(),buffer.getLong()); }
}
