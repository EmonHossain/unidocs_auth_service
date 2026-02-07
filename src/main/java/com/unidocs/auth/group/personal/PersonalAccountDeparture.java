package com.unidocs.auth.group.personal;

import java.time.Instant;
import java.sql.Timestamp;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Existing account lifecycle use cases call this inside their current account-group fence/transaction. */
@Component
public class PersonalAccountDeparture {
    private final JdbcTemplate jdbc;
    public PersonalAccountDeparture(JdbcTemplate jdbc){this.jdbc=jdbc;}
    public void assertDepartureAllowed(UUID accountId,Instant now,boolean softRemoval){
        requireTransaction();
        if(accountId==null || now==null)throw new IllegalArgumentException("Account departure requires current account and instant.");
        fence();
        String closing=softRemoval?"":" OR(g.status='CLOSING' AND g.purge_after>?)";
        List<byte[]> owned=jdbc.query("SELECT g.id FROM iam_group g WHERE g.created_by_account_id=? AND g.workspace_context='INDIVIDUAL' AND (g.status IN('ACTIVE','PREPARING')"+closing+") ORDER BY g.id LIMIT 1 FOR UPDATE",(rs,n)->rs.getBytes(1),softRemoval?new Object[]{bytes(accountId)}:new Object[]{bytes(accountId),Timestamp.from(now)});
        if(!owned.isEmpty())throw new ResponseStatusException(HttpStatus.CONFLICT,"PERSONAL_GROUP_OWNER_DEPARTURE_BLOCKED");
    }
    public void depart(UUID accountId,Instant now,UUID actorAccountId,UUID userId,UUID sessionId){
        assertDepartureAllowed(accountId,now,false);
        Objects.requireNonNull(userId);
        UUID after=null;
        while(true){
            String sql="""
                SELECT g.id FROM iam_group g WHERE g.workspace_context='INDIVIDUAL'
                AND (EXISTS(SELECT 1 FROM personal_group_member m WHERE m.group_id=g.id AND m.account_id=? AND m.status='ACTIVE')
                  OR EXISTS(SELECT 1 FROM personal_group_invitation i WHERE i.group_id=g.id AND i.status='PENDING' AND (i.sender_account_id=? OR i.recipient_account_id=?)))
                """+(after==null?"":" AND g.id>?")+" ORDER BY g.id LIMIT 100";
            List<UUID> page=jdbc.query(sql,(rs,n)->uuid(rs.getBytes(1)),after==null?new Object[]{bytes(accountId),bytes(accountId),bytes(accountId)}:new Object[]{bytes(accountId),bytes(accountId),bytes(accountId),bytes(after)});
            if(page.isEmpty())break;
            for(UUID group:page)revoke(group,accountId,now,actorAccountId,userId,sessionId);
            after=page.getLast();
        }
        Timestamp timestamp=Timestamp.from(now);
        int revoked=jdbc.update("UPDATE iam_developer_eligibility SET status='REVOKED',version=version+1,reason='Revoked by account departure',updated_at=? WHERE account_id=? AND status='ACTIVE'",timestamp,bytes(accountId));
        jdbc.update("DELETE FROM iam_developer_factor WHERE account_id=?",bytes(accountId));
        if(revoked>0){
            long version=jdbc.queryForObject("SELECT version FROM iam_developer_eligibility WHERE account_id=?",Long.class,bytes(accountId));
            UUID event=UUID.randomUUID();
            jdbc.update("INSERT INTO iam_controlplane_audit(id,account_id,session_id,action_key,aggregate_id,aggregate_version,reason,occurred_at) VALUES(?,?,?,'DEVELOPER_ACCOUNT_DEPARTED',?,?, 'Revoked by account departure',?)",bytes(event),bytes(accountId),sessionId==null?null:bytes(sessionId),bytes(accountId),version,timestamp);
            outbox(event,"DEVELOPER_ELIGIBILITY",accountId,version,"DEVELOPER_ELIGIBILITY_REVOKED",accountId,actorAccountId,userId,sessionId,null,now);
        }
    }
    private void revoke(UUID group,UUID account,Instant now,UUID actor,UUID user,UUID session){
        List<Long> versions=jdbc.query("SELECT version FROM iam_group WHERE id=? AND workspace_context='INDIVIDUAL' FOR UPDATE",(rs,n)->rs.getLong(1),bytes(group));
        if(versions.size()!=1)throw new ResponseStatusException(HttpStatus.CONFLICT,"PERSONAL_GROUP_STATE_CHANGED");
        Timestamp timestamp=Timestamp.from(now);
        int members=jdbc.update("UPDATE personal_group_member SET status='REVOKED',version=version+1,revoked_at=? WHERE group_id=? AND account_id=? AND status='ACTIVE'",timestamp,bytes(group),bytes(account));
        int invitations=jdbc.update("UPDATE personal_group_invitation SET status='REVOKED',version=version+1,responded_at=? WHERE group_id=? AND status='PENDING' AND (sender_account_id=? OR recipient_account_id=?)",timestamp,bytes(group),bytes(account),bytes(account));
        if(members+invitations==0)return;
        long version=versions.getFirst()+1;UUID event=UUID.randomUUID();
        jdbc.update("UPDATE iam_group SET version=?,updated_at=? WHERE id=?",version,timestamp,bytes(group));
        jdbc.update("INSERT INTO personal_group_audit(id,group_id,account_id,session_id,event_type,group_version,occurred_at) VALUES(?,?,?,?,'PERSONAL_GROUP_ACCOUNT_DEPARTED',?,?)",bytes(event),bytes(group),bytes(actor==null?account:actor),session==null?null:bytes(session),version,timestamp);
        outbox(event,"PERSONAL_GROUP",group,version,"PERSONAL_GROUP_ACCOUNT_DEPARTED",account,actor,user,session,group,now);
        jdbc.update("INSERT INTO account_security_notice(id,user_id,account_id,code,reason,created_at,available_at) VALUES(?,?,?,'PERSONAL_GROUP_ACCOUNT_DEPARTED','Your account departure revoked personal collaboration membership and pending invitations.',?,?)",bytes(UUID.randomUUID()),bytes(user),bytes(account),timestamp,timestamp);
    }
    private void outbox(UUID event,String type,UUID aggregate,long version,String action,UUID account,UUID actor,UUID user,UUID session,UUID group,Instant now){
        String payload="{\"eventId\":\"%s\",\"eventType\":\"%s\",\"sourceService\":\"auth-service\",\"schemaVersion\":1,\"aggregateType\":\"%s\",\"aggregateId\":\"%s\",\"aggregateVersion\":%d,\"accountId\":\"%s\",\"userId\":\"%s\",\"actorAccountId\":%s,\"actorUserId\":%s,\"actorService\":%s,\"sessionId\":%s,\"groupId\":%s,\"occurredAt\":\"%s\"}".formatted(event,action,type,aggregate,version,account,user,json(actor),actor==null?"null":json(user),actor==null?"\"auth-service\"":"null",json(session),json(group),now);
        Timestamp timestamp=Timestamp.from(now);
        jdbc.update("INSERT INTO outbox_event(id,aggregate_type,aggregate_id,aggregate_version,event_type,payload,status,attempts,created_at,available_at) VALUES(?,?,?,?,?,?,'PENDING',0,?,?)",bytes(event),type,bytes(aggregate),version,action,payload,timestamp,timestamp);
    }
    private void fence(){jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR SHARE",Long.class);}
    private static void requireTransaction(){if(!TransactionSynchronizationManager.isActualTransactionActive())throw new IllegalStateException("Personal account departure requires the caller's fenced transaction.");}
    private static String json(UUID value){return value==null?"null":"\""+value+"\"";}
    private static UUID uuid(byte[] bytes){java.nio.ByteBuffer buffer=java.nio.ByteBuffer.wrap(bytes);return new UUID(buffer.getLong(),buffer.getLong());}
}
