package com.unidocs.auth.group.personal;

import java.time.Clock;
import java.time.Instant;
import java.sql.Timestamp;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.transaction.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

/** Service-only lifecycle intent: never a visibility or user permission grant. */
@Service
public class PersonalGroupClosureService {
    public record Closure(UUID groupId,long groupVersion,UUID ownerAccountId,UUID ownerUserId,String status,
            long noticeSeconds,Instant purgeAfter,Instant deletionRequestedAt,Instant checkedAt,boolean purgeEligible) { }
    public record Page(List<Closure> items,UUID nextCursor) { }
    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final com.unidocs.auth.student.StudentClosureService students;
    public PersonalGroupClosureService(JdbcTemplate jdbc,Clock clock,com.unidocs.auth.student.StudentClosureService students){this.jdbc=jdbc;this.clock=clock;this.students=students;}
    @PreAuthorize("isAuthenticated() and hasAuthority('SCOPE_iam.authorization.read')")
    @Transactional(propagation=Propagation.REQUIRES_NEW,isolation=Isolation.READ_COMMITTED)
    public Page closures(Authentication service,UUID after,int limit){
        requireService(service);
        if(limit<1 || limit>100)throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"INVALID_PAGE_LIMIT");
        fence();
        List<Closure> rows=jdbc.query(SELECT+" WHERE g.organization_id IS NULL AND g.workspace_context='INDIVIDUAL' AND g.status IN('PREPARING','CLOSING')"
            +(after==null?"":" AND g.id>?")+" ORDER BY g.id LIMIT ? FOR SHARE OF g",this::map,
            after==null?new Object[]{limit+1}:new Object[]{bytes(after),limit+1});
        requireService(service);
        List<Closure> combined=new ArrayList<>(rows);combined.addAll(students.closures(service,after,limit+1));
        combined.sort(Comparator.comparing(item->item.groupId().toString()));
        boolean more=combined.size()>limit;List<Closure> page=List.copyOf(combined.subList(0,Math.min(combined.size(),limit)));
        return new Page(page,more?page.getLast().groupId():null);
    }
    @PreAuthorize("isAuthenticated() and hasAuthority('SCOPE_iam.authorization.read')")
    @Transactional(propagation=Propagation.REQUIRES_NEW,isolation=Isolation.READ_COMMITTED)
    public Closure state(Authentication service,UUID groupId){
        requireService(service);if(student(groupId)) return students.state(service,groupId);
        requireService(service);fence();Closure value=read(groupId,false);requireService(service);return value;
    }
    @PreAuthorize("isAuthenticated() and hasAuthority('SCOPE_iam.authorization.read')")
    @Transactional(propagation=Propagation.REQUIRES_NEW,isolation=Isolation.READ_COMMITTED)
    public Closure confirmNotices(Authentication service,UUID groupId,long expectedGroupVersion,UUID noticeBatchId){
        requireService(service);if(student(groupId)) return students.confirm(service,groupId,expectedGroupVersion,noticeBatchId);
        requireService(service);
        if(expectedGroupVersion<1 || noticeBatchId==null)throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"INVALID_NOTICE_RECEIPT");
        fence();Closure before=read(groupId,true);
        List<UUID> batches=jdbc.query("SELECT deletion_notice_batch_id FROM iam_group WHERE id=?",(rs,n)->rs.getBytes(1)==null?null:uuid(rs.getBytes(1)),bytes(groupId));
        UUID prior=batches.getFirst();
        if("CLOSING".equals(before.status())){
            if(prior!=null && prior.equals(noticeBatchId)){requireService(service);return before;}
            throw conflict();
        }
        if(!"PREPARING".equals(before.status()) || before.groupVersion()!=expectedGroupVersion)throw conflict();
        requireService(service);
        Instant now=clock.instant(),deadline=now.plusSeconds(before.noticeSeconds());Timestamp timestamp=Timestamp.from(now);
        jdbc.update("UPDATE iam_group SET status='CLOSING',purge_after=?,deletion_notice_batch_id=?,version=version+1,updated_at=? WHERE id=?",
            Timestamp.from(deadline),bytes(noticeBatchId),timestamp,bytes(groupId));
        long version=before.groupVersion()+1;
        jdbc.update("""
            INSERT INTO account_security_notice(id,user_id,account_id,code,reason,deadline,created_at,available_at)
            SELECT UUID_TO_BIN(UUID()),a.user_id,a.id,'PERSONAL_GROUP_DELETION_SCHEDULED',
            'This group is scheduled for deletion. Copy content you need before the stated deadline.',?,?,?
            FROM personal_group_member m JOIN user_account a ON a.id=m.account_id WHERE m.group_id=?
            """,Timestamp.from(deadline),timestamp,timestamp,bytes(groupId));
        UUID event=UUID.randomUUID();
        jdbc.update("INSERT INTO personal_group_audit(id,group_id,account_id,session_id,event_type,group_version,occurred_at) VALUES(?,?,?,NULL,'PERSONAL_GROUP_DELETION_SCHEDULED',?,?)",
            bytes(event),bytes(groupId),bytes(before.ownerAccountId()),version,timestamp);
        String payload="{\"eventId\":\"%s\",\"eventType\":\"PERSONAL_GROUP_DELETION_SCHEDULED\",\"sourceService\":\"auth-service\",\"schemaVersion\":1,\"aggregateType\":\"PERSONAL_GROUP\",\"aggregateId\":\"%s\",\"aggregateVersion\":%d,\"groupId\":\"%s\",\"ownerAccountId\":\"%s\",\"actorUserId\":\"%s\",\"sessionId\":null,\"noticeBatchId\":\"%s\",\"workspaceContext\":\"INDIVIDUAL\",\"deadline\":\"%s\",\"occurredAt\":\"%s\"}".formatted(event,groupId,version,groupId,before.ownerAccountId(),before.ownerUserId(),noticeBatchId,deadline,now);
        jdbc.update("INSERT INTO outbox_event(id,aggregate_type,aggregate_id,aggregate_version,event_type,payload,status,attempts,created_at,available_at) VALUES(?,'PERSONAL_GROUP',?,?,'PERSONAL_GROUP_DELETION_SCHEDULED',?,'PENDING',0,?,?)",
            bytes(event),bytes(groupId),version,payload,timestamp,timestamp);
        requireService(service);
        return read(groupId,false);
    }
    private static final String SELECT="SELECT g.id,g.version,g.created_by_account_id,a.user_id,g.status,g.deletion_notice_seconds,g.purge_after,g.deletion_requested_at FROM iam_group g JOIN user_account a ON a.id=g.created_by_account_id";
    private boolean student(UUID group) { return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_study_group WHERE id=?)",Boolean.class,bytes(group))); }
    private Closure read(UUID group,boolean exclusive){
        if(group==null)throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"INVALID_GROUP");
        List<Closure> rows=jdbc.query(SELECT+" WHERE g.id=? AND g.workspace_context='INDIVIDUAL' AND g.organization_id IS NULL "+(exclusive?"FOR UPDATE OF g":"FOR SHARE OF g"),this::map,bytes(group));
        if(rows.size()!=1)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"GROUP_NOT_FOUND");
        return rows.getFirst();
    }
    private Closure map(java.sql.ResultSet rows,int row)throws java.sql.SQLException{
        Timestamp purge=rows.getTimestamp("purge_after"),requested=rows.getTimestamp("deletion_requested_at");
        Instant checked=clock.instant();String status=rows.getString("status");
        return new Closure(uuid(rows.getBytes("id")),rows.getLong("version"),uuid(rows.getBytes("created_by_account_id")),uuid(rows.getBytes("user_id")),status,rows.getLong("deletion_notice_seconds"),purge==null?null:purge.toInstant(),requested==null?null:requested.toInstant(),checked,"CLOSING".equals(status) && purge!=null && !checked.isBefore(purge.toInstant()));
    }
    private void fence(){jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL' FOR SHARE",Long.class);}
    private void requireService(Authentication authentication){
        if(authentication!=SecurityContextHolder.getContext().getAuthentication()
                || !(authentication instanceof JwtAuthenticationToken token) || !token.isAuthenticated()
                || token.getToken().getExpiresAt()==null || !clock.instant().isBefore(token.getToken().getExpiresAt())
                || !("document-service".equals(token.getToken().getClaimAsString("azp")) || "document-service".equals(token.getName())))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,"SERVICE_OPERATION_NOT_ALLOWED");
    }
    private static ResponseStatusException conflict(){return new ResponseStatusException(HttpStatus.CONFLICT,"GROUP_NOTICE_RECEIPT_CONFLICT");}
    private static UUID uuid(byte[] bytes){java.nio.ByteBuffer buffer=java.nio.ByteBuffer.wrap(bytes);return new UUID(buffer.getLong(),buffer.getLong());}
}
