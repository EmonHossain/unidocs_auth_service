package com.unidocs.auth.group.persistence;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static com.unidocs.auth.group.persistence.GroupRuleRepository.*;

@Repository
public class GroupInvitationRepository {
    public record Invitation(UUID id,UUID organizationId,UUID groupId,UUID accountId,UUID anchor,UUID issuer,UUID request,
            String fingerprint,String role,Instant validFrom,Instant validUntil,Instant expiresAt,String status,long version,UUID membershipId) { }
    private final JdbcTemplate jdbc;
    public GroupInvitationRepository(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    public Optional<Invitation> find(UUID organization,UUID id) {
        return jdbc.query("SELECT * FROM group_invitation WHERE organization_id=? AND id=?",(rs,row)->map(rs),bytes(organization),bytes(id)).stream().findFirst();
    }
    public Optional<Invitation> retry(UUID organization,UUID issuer,UUID request) {
        return jdbc.query("SELECT * FROM group_invitation WHERE organization_id=? AND issued_by=? AND request_id=?",(rs,row)->map(rs),bytes(organization),bytes(issuer),bytes(request)).stream().findFirst();
    }
    public void create(Invitation i,Instant now) {
        jdbc.update("""
            INSERT INTO group_invitation(id,organization_id,group_id,account_id,organization_membership_id,issued_by,request_id,fingerprint,
              role,valid_from,valid_until,expires_at,status,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'PENDING',1,?,?)
            """,bytes(i.id()),bytes(i.organizationId()),bytes(i.groupId()),bytes(i.accountId()),bytes(i.anchor()),bytes(i.issuer()),bytes(i.request()),
                i.fingerprint(),i.role(),time(i.validFrom()),time(i.validUntil()),time(i.expiresAt()),time(now),time(now));
    }
    public void finish(UUID id,UUID membership,Instant now) {
        jdbc.update("UPDATE group_invitation SET status=?,membership_id=?,version=version+1,updated_at=? WHERE id=? AND status='PENDING'",
                membership==null?"REVOKED":"ACCEPTED",nullable(membership),time(now),bytes(id));
    }
    public List<Invitation> pending(UUID organization,UUID anchor,UUID after,int limit,Instant now) {
        String sql="SELECT * FROM group_invitation WHERE organization_id=? AND organization_membership_id=? AND status='PENDING' AND expires_at>?";
        return jdbc.query(sql+(after==null?"":" AND id>?")+" ORDER BY id LIMIT ?",(rs,row)->map(rs),after==null?
                new Object[]{bytes(organization),bytes(anchor),time(now),limit}:new Object[]{bytes(organization),bytes(anchor),time(now),bytes(after),limit});
    }
    private static Invitation map(ResultSet rs)throws SQLException {
        return new Invitation(uuid(rs.getBytes("id")),uuid(rs.getBytes("organization_id")),uuid(rs.getBytes("group_id")),uuid(rs.getBytes("account_id")),
                uuid(rs.getBytes("organization_membership_id")),uuid(rs.getBytes("issued_by")),uuid(rs.getBytes("request_id")),rs.getString("fingerprint"),
                rs.getString("role"),rs.getTimestamp("valid_from").toInstant(),rs.getTimestamp("valid_until")==null?null:rs.getTimestamp("valid_until").toInstant(),
                rs.getTimestamp("expires_at").toInstant(),rs.getString("status"),rs.getLong("version"),uuid(rs.getBytes("membership_id")));
    }
}
