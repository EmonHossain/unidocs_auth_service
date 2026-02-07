package com.unidocs.auth.group.personal;

import java.time.Instant;
import java.sql.Timestamp;
import java.util.*;
import com.unidocs.auth.session.application.SessionAccess;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Caller holds its session/account-group fence, then the current GLOBAL policy fence. */
@Component
public class PersonalGroupAccess {
    public record Membership(UUID groupId,UUID membershipId,UUID ownerAccountId,String status,long groupVersion,long memberVersion,Instant purgeAfter,boolean owner) { }
    private final JdbcTemplate jdbc;
    private final java.time.Clock clock;
    @org.springframework.beans.factory.annotation.Autowired
    public PersonalGroupAccess(JdbcTemplate jdbc,java.time.Clock clock){this.jdbc=jdbc;this.clock=clock;}
    public PersonalGroupAccess(JdbcTemplate jdbc){this(jdbc,java.time.Clock.systemUTC());}
    public Membership require(SessionAccess.Context context,UUID account,UUID group,boolean write){
        List<Membership> memberships=jdbc.query("""
            SELECT g.id,g.created_by_account_id,g.status,g.version,g.purge_after,m.id AS membership_id,m.version AS member_version
            FROM iam_group g JOIN personal_group_member m ON m.group_id=g.id
            JOIN user_account a ON a.id=m.account_id JOIN users u ON u.id=a.user_id
            WHERE g.id=? AND g.workspace_context='INDIVIDUAL' AND g.organization_id IS NULL
            AND m.account_id=? AND m.status='ACTIVE' AND a.type='PERSONAL' AND a.status='ACTIVE' AND u.status='ACTIVE'
            AND (g.status IN ('ACTIVE','PREPARING') OR (g.status='CLOSING' AND g.purge_after>?)) FOR UPDATE
            """,(rs,n)->new Membership(id(rs,"id"),id(rs,"membership_id"),id(rs,"created_by_account_id"),rs.getString("status"),rs.getLong("version"),rs.getLong("member_version"),rs.getTimestamp("purge_after")==null?null:rs.getTimestamp("purge_after").toInstant(),id(rs,"created_by_account_id").equals(account)),bytes(group),bytes(account),Timestamp.from(clock.instant()));
        if(memberships.size()!=1 || write && !"ACTIVE".equals(memberships.getFirst().status()))throw denied();
        if("CLOSING".equals(memberships.getFirst().status()) && !clock.instant().isBefore(memberships.getFirst().purgeAfter()))throw denied();
        return memberships.getFirst();
    }
    static ResponseStatusException denied(){return new ResponseStatusException(HttpStatus.FORBIDDEN,"PERSONAL_GROUP_ACCESS_DENIED");}
    private static UUID id(java.sql.ResultSet rows,String column)throws java.sql.SQLException{java.nio.ByteBuffer value=java.nio.ByteBuffer.wrap(rows.getBytes(column));return new UUID(value.getLong(),value.getLong());}
}
