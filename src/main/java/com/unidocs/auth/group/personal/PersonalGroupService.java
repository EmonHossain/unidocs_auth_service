package com.unidocs.auth.group.personal;

import java.time.*;
import java.sql.Timestamp;
import java.util.*;
import java.util.function.Function;
import com.unidocs.auth.authentication.application.AuthenticationFailure;
import com.unidocs.auth.authorization.application.OperationAuthorizationService;
import com.unidocs.auth.group.domain.Group;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.persistence.SessionRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Service
@Transactional(propagation=Propagation.NEVER)
public class PersonalGroupService {
    public record GroupView(UUID id,String name,UUID ownerAccountId,String status,long version,Instant purgeAfter,boolean owner) { }
    public record GroupPage(List<GroupView> items,UUID nextCursor) { }
    public record Invitation(UUID id,UUID groupId,UUID senderAccountId,UUID recipientAccountId,String status,long version,Instant createdAt,Instant expiresAt) { }
    public record InvitationPage(List<Invitation> items,UUID nextCursor) { }
    public record Member(UUID accountId,String displayName,boolean owner,long version,Instant joinedAt) { }
    public record MemberPage(List<Member> items,UUID nextCursor) { }
    private final JdbcTemplate jdbc;
    private final SessionAccess access;
    private final SessionRepository sessions;
    private final PersonalGroupAccess groups;
    private final OperationAuthorizationService policy;
    private final Clock clock;
    private final long noticeSeconds;
    public PersonalGroupService(JdbcTemplate jdbc,SessionAccess access,SessionRepository sessions,PersonalGroupAccess groups,
            OperationAuthorizationService policy,Clock clock,org.springframework.core.env.Environment environment){
        this.jdbc=jdbc;this.access=access;this.sessions=sessions;this.groups=groups;this.policy=policy;this.clock=clock;
        long configured=environment.getProperty("auth.personal-groups.test-notice-seconds",Long.class,604800L);
        noticeSeconds=Arrays.asList(environment.getActiveProfiles()).contains("test")?Math.max(2,Math.min(604800,configured)):604800;
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public GroupView create(Jwt jwt,UUID account,String name,UUID request){
        if(request==null)throw bad();
        String normalized=Group.normalizedName(name);String fingerprint=hash(normalized);
        return execute(jwt,account,"group.create",null,context->{
            List<Map<String,Object>> previous=jdbc.queryForList("SELECT id,creation_fingerprint FROM iam_group WHERE workspace_context='INDIVIDUAL' AND created_by_account_id=? AND creation_request_id=?",bytes(account),bytes(request));
            if(!previous.isEmpty()){
                Map<String,Object> row=previous.getFirst();if(!fingerprint.equals(row.get("creation_fingerprint")))throw conflict();
                return group(uuid((byte[])row.get("id")),account);
            }
            UUID identity=UUID.randomUUID();Timestamp now=Timestamp.from(context.now());
            jdbc.update("INSERT INTO iam_group(id,organization_id,name,type,status,version,created_by_account_id,creation_request_id,creation_fingerprint,created_at,updated_at,workspace_context) VALUES(?,NULL,?,'CUSTOM','ACTIVE',1,?,?,?,?,?,'INDIVIDUAL')",bytes(identity),normalized,bytes(account),bytes(request),fingerprint,now,now);
            jdbc.update("INSERT INTO personal_group_member(id,group_id,account_id,status,version,joined_at) VALUES(?,?,?,'ACTIVE',1,?)",bytes(UUID.randomUUID()),bytes(identity),bytes(account),now);
            changed(context,account,identity,"PERSONAL_GROUP_CREATED",false,null,false);
            return group(identity,account);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public GroupView get(Jwt jwt,UUID account,UUID group){return execute(jwt,account,"group.read",group,context->{groups.require(context,account,group,false);return group(group,account);});}
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public GroupPage list(Jwt jwt,UUID account,UUID after,int limit){
        bounded(limit);
        return execute(jwt,account,"group.read",null,context->{
            List<GroupView> rows=jdbc.query("SELECT g.* FROM iam_group g JOIN personal_group_member m ON m.group_id=g.id WHERE m.account_id=? AND m.status='ACTIVE' AND g.workspace_context='INDIVIDUAL' AND (g.status='ACTIVE' OR (g.status='CLOSING' AND g.purge_after>?))"+(after==null?"":" AND g.id>?")+" ORDER BY g.id LIMIT ?",(rs,n)->view(rs,account),after==null?new Object[]{bytes(account),Timestamp.from(context.now()),limit+1}:new Object[]{bytes(account),Timestamp.from(context.now()),bytes(after),limit+1});
            boolean more=rows.size()>limit;List<GroupView> page=List.copyOf(rows.subList(0,Math.min(rows.size(),limit)));
            return new GroupPage(page,more?page.getLast().id():null);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public Invitation invite(Jwt jwt,UUID account,UUID group,UUID recipient,UUID request){
        if(recipient==null || request==null || recipient.equals(account))throw bad();
        return execute(jwt,account,"group.invitation.issue",group,context->{
            owner(groups.require(context,account,group,true));
            personal(recipient);
            List<Invitation> repeated=jdbc.query("SELECT * FROM personal_group_invitation WHERE group_id=? AND sender_account_id=? AND creation_request_id=?",(rs,n)->mapInvitation(rs,n),bytes(group),bytes(account),bytes(request));
            if(!repeated.isEmpty()){if(!repeated.getFirst().recipientAccountId().equals(recipient))throw conflict();return repeated.getFirst();}
            if(!jdbc.queryForList("SELECT account_id FROM personal_group_member WHERE group_id=? AND account_id=? AND status='ACTIVE'",bytes(group),bytes(recipient)).isEmpty())throw conflict();
            jdbc.update("UPDATE personal_group_invitation SET status='REVOKED',version=version+1,responded_at=? WHERE group_id=? AND recipient_account_id=? AND status='PENDING' AND expires_at<=?",Timestamp.from(context.now()),bytes(group),bytes(recipient),Timestamp.from(context.now()));
            if(!jdbc.queryForList("SELECT id FROM personal_group_invitation WHERE group_id=? AND recipient_account_id=? AND status='PENDING'",bytes(group),bytes(recipient)).isEmpty())throw conflict();
            UUID identity=UUID.randomUUID();Timestamp now=Timestamp.from(context.now());
            jdbc.update("INSERT INTO personal_group_invitation(id,group_id,sender_account_id,recipient_account_id,status,version,creation_request_id,created_at,expires_at) VALUES(?,?,?,?,'PENDING',1,?,?,?)",bytes(identity),bytes(group),bytes(account),bytes(recipient),bytes(request),now,Timestamp.from(context.now().plus(Duration.ofDays(7))));
            changed(context,account,group,"PERSONAL_GROUP_INVITATION_ISSUED",true,null,false);notice(recipient,"PERSONAL_GROUP_INVITATION","A personal collaboration group invitation is awaiting your decision.",null,context.now());
            return invitation(identity);
        },recipient);
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public InvitationPage invitations(Jwt jwt,UUID account,UUID after,int limit){
        bounded(limit);
        return execute(jwt,account,"group.read",null,context->{
            List<Invitation> rows=jdbc.query("SELECT i.* FROM personal_group_invitation i JOIN iam_group g ON g.id=i.group_id WHERE i.recipient_account_id=? AND i.status='PENDING' AND i.expires_at>? AND g.workspace_context='INDIVIDUAL' AND g.status='ACTIVE'"+(after==null?"":" AND i.id>?")+" ORDER BY i.id LIMIT ?",(rs,n)->mapInvitation(rs,n),after==null?new Object[]{bytes(account),Timestamp.from(context.now()),limit+1}:new Object[]{bytes(account),Timestamp.from(context.now()),bytes(after),limit+1});
            boolean more=rows.size()>limit;List<Invitation> page=List.copyOf(rows.subList(0,Math.min(rows.size(),limit)));
            return new InvitationPage(page,more?page.getLast().id():null);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public MemberPage members(Jwt jwt,UUID account,UUID group,UUID after,int limit){
        bounded(limit);
        return execute(jwt,account,"group.read",group,context->{
            groups.require(context,account,group,false);
            List<Member> rows=jdbc.query("SELECT m.account_id,a.display_name,m.version,m.joined_at,g.created_by_account_id FROM personal_group_member m JOIN iam_group g ON g.id=m.group_id JOIN user_account a ON a.id=m.account_id JOIN users u ON u.id=a.user_id WHERE m.group_id=? AND m.status='ACTIVE' AND a.status='ACTIVE' AND u.status='ACTIVE'"+(after==null?"":" AND m.account_id>?")+" ORDER BY m.account_id LIMIT ?",(rs,n)->new Member(id(rs,"account_id"),rs.getString("display_name"),id(rs,"account_id").equals(id(rs,"created_by_account_id")),rs.getLong("version"),rs.getTimestamp("joined_at").toInstant()),after==null?new Object[]{bytes(group),limit+1}:new Object[]{bytes(group),bytes(after),limit+1});
            boolean more=rows.size()>limit;List<Member> page=List.copyOf(rows.subList(0,Math.min(rows.size(),limit)));
            return new MemberPage(page,more?page.getLast().accountId():null);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public InvitationPage outgoing(Jwt jwt,UUID account,UUID group,UUID after,int limit){
        bounded(limit);
        return execute(jwt,account,"group.invitation.revoke",group,context->{
            owner(groups.require(context,account,group,true));
            List<Invitation> rows=jdbc.query("SELECT i.* FROM personal_group_invitation i WHERE i.group_id=? AND i.status='PENDING' AND i.expires_at>?"+(after==null?"":" AND i.id>?")+" ORDER BY i.id LIMIT ?",(rs,n)->mapInvitation(rs,n),after==null?new Object[]{bytes(group),Timestamp.from(clock.instant()),limit+1}:new Object[]{bytes(group),Timestamp.from(clock.instant()),bytes(after),limit+1});
            boolean more=rows.size()>limit;List<Invitation> page=List.copyOf(rows.subList(0,Math.min(rows.size(),limit)));
            return new InvitationPage(page,more?page.getLast().id():null);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public Invitation respond(Jwt jwt,UUID account,UUID invitationId,boolean accept){
        List<UUID> senders=jdbc.query("SELECT sender_account_id FROM personal_group_invitation WHERE id=? AND recipient_account_id=?",(rs,n)->id(rs,"sender_account_id"),bytes(invitationId),bytes(account));
        if(senders.size()!=1)throw PersonalGroupAccess.denied();
        return execute(jwt,account,accept?"group.invitation.accept":"group.invitation.decline",null,context->{
            Invitation initial=invitation(invitationId);if(!initial.recipientAccountId().equals(account))throw PersonalGroupAccess.denied();
            lockGroup(initial.groupId(),true,context.now());
            Invitation current=invitation(invitationId);
            String desired=accept?"ACCEPTED":"DECLINED";
            if(desired.equals(current.status()))return current;
            if(!"PENDING".equals(current.status()) || !current.expiresAt().isAfter(clock.instant()))throw PersonalGroupAccess.denied();
            personal(current.senderAccountId());personal(account);
            jdbc.update("UPDATE personal_group_invitation SET status=?,version=version+1,responded_at=? WHERE id=?",desired,Timestamp.from(context.now()),bytes(invitationId));
            if(accept)jdbc.update("INSERT INTO personal_group_member(id,group_id,account_id,status,version,joined_at) VALUES(?,?,?,'ACTIVE',1,?) ON DUPLICATE KEY UPDATE status='ACTIVE',version=version+1,joined_at=VALUES(joined_at),revoked_at=NULL",bytes(UUID.randomUUID()),bytes(current.groupId()),bytes(account),Timestamp.from(context.now()));
            changed(context,account,current.groupId(),accept?"PERSONAL_GROUP_MEMBER_JOINED":"PERSONAL_GROUP_INVITATION_DECLINED",true,null,true);
            notice(account,accept?"PERSONAL_GROUP_JOINED":"PERSONAL_GROUP_INVITATION_DECLINED",accept?"Your personal collaboration group invitation was accepted.":"Your personal collaboration group invitation was declined.",null,context.now());
            return invitation(invitationId);
        },senders.getFirst());
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public Invitation revoke(Jwt jwt,UUID account,UUID group,UUID invitationId){
        return execute(jwt,account,"group.invitation.revoke",group,context->{
            owner(groups.require(context,account,group,true));Invitation invitation=invitation(invitationId);
            if(!invitation.groupId().equals(group))throw PersonalGroupAccess.denied();
            if("REVOKED".equals(invitation.status()))return invitation;
            if(!"PENDING".equals(invitation.status()))throw conflict();
            jdbc.update("UPDATE personal_group_invitation SET status='REVOKED',version=version+1,responded_at=? WHERE id=?",Timestamp.from(context.now()),bytes(invitationId));
            changed(context,account,group,"PERSONAL_GROUP_INVITATION_REVOKED",true,null,false);
            notice(invitation.recipientAccountId(),"PERSONAL_GROUP_INVITATION_REVOKED","Your personal collaboration group invitation was revoked.",null,context.now());
            return invitation(invitationId);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public boolean remove(Jwt jwt,UUID account,UUID group,UUID target,boolean leave){
        if(target==null || leave&&!target.equals(account))throw bad();
        return execute(jwt,account,leave?"group.leave":"group.member.remove",group,context->{
            PersonalGroupAccess.Membership membership=groups.require(context,account,group,true);
            if(!leave)owner(membership);
            if(membership.ownerAccountId().equals(target))throw new ResponseStatusException(HttpStatus.CONFLICT,"GROUP_OWNER_CANNOT_LEAVE");
            int changed=jdbc.update("UPDATE personal_group_member SET status='REVOKED',version=version+1,revoked_at=? WHERE group_id=? AND account_id=? AND status='ACTIVE'",Timestamp.from(context.now()),bytes(group),bytes(target));
            if(changed>0){changed(context,account,group,leave?"PERSONAL_GROUP_MEMBER_LEFT":"PERSONAL_GROUP_MEMBER_REMOVED",true,null,true);notice(target,"PERSONAL_GROUP_ACCESS_REVOKED","Your personal collaboration group membership has ended.",null,context.now());}
            return true;
        },target);
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public GroupView scheduleDeletion(Jwt jwt,UUID account,UUID group){
        return execute(jwt,account,"group.delete.schedule",group,context->{
            PersonalGroupAccess.Membership membership=groups.require(context,account,group,false);owner(membership);
            if(Set.of("PREPARING","CLOSING").contains(membership.status()))return group(group,account);
            if(noticeSeconds<604800 && !Set.of("auth_service_test","auth_service_test_app").contains(jdbc.queryForObject("SELECT DATABASE()",String.class)))
                throw new IllegalStateException("Short group notice windows require the isolated test schema");
            jdbc.update("UPDATE iam_group SET status='PREPARING',purge_after=NULL,deletion_requested_at=?,deletion_notice_seconds=?,deletion_notice_batch_id=NULL,version=version+1,updated_at=? WHERE id=?",Timestamp.from(context.now()),noticeSeconds,Timestamp.from(context.now()),bytes(group));
            jdbc.update("UPDATE personal_group_invitation SET status='REVOKED',version=version+1,responded_at=? WHERE group_id=? AND status='PENDING'",Timestamp.from(context.now()),bytes(group));
            changed(context,account,group,"PERSONAL_GROUP_DELETION_PREPARING",false,null,false);
            return group(group,account);
        });
    }
    @PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication, #p0)")
    public GroupView cancelDeletion(Jwt jwt,UUID account,UUID group){
        return execute(jwt,account,"group.delete.cancel",group,context->{
            PersonalGroupAccess.Membership membership=groups.require(context,account,group,false);owner(membership);
            if("ACTIVE".equals(membership.status()))return group(group,account);
            if(!Set.of("PREPARING","CLOSING").contains(membership.status()))throw PersonalGroupAccess.denied();
            if(membership.purgeAfter()!=null && !clock.instant().isBefore(membership.purgeAfter()))throw PersonalGroupAccess.denied();
            jdbc.update("UPDATE iam_group SET status='ACTIVE',purge_after=NULL,deletion_requested_at=NULL,deletion_notice_batch_id=NULL,version=version+1,updated_at=? WHERE id=?",Timestamp.from(clock.instant()),bytes(group));
            changed(context,account,group,"PERSONAL_GROUP_DELETION_CANCELLED",false,null,true);
            return group(group,account);
        });
    }
    private <T> T execute(Jwt jwt,UUID account,String operation,UUID group,Function<SessionAccess.Context,T> command,UUID... targetAccounts){
        if(jwt==null || account==null)throw new AuthenticationFailure();
        Map<UUID,UUID> targetFences=new HashMap<>();
        for(UUID target:targetAccounts)targetFences.put(target,targetGroup(target));
        com.unidocs.auth.security.spicedb.IndividualSpiceDbGuard.Decision graphDecision = policy.prepareIndividual(jwt,account,operation,group);
        Function<SessionAccess.Context,T> work=context->{
            if(jwt.getExpiresAt()==null || !jwt.getExpiresAt().isAfter(context.now()))throw new AuthenticationFailure();
            for(Map.Entry<UUID,UUID> target:targetFences.entrySet())if(!Objects.equals(target.getValue(),targetGroup(target.getKey())))throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,"RETRY_ACCOUNT_FENCE");
            policy.authorizeIndividual(context,account,operation,group,graphDecision);
            if(!jwt.getExpiresAt().isAfter(clock.instant()))throw new AuthenticationFailure();
            personal(account);
            Instant current=clock.instant();
            if(!context.session().activeAt(current))throw new AuthenticationFailure();
            com.unidocs.auth.session.domain.SessionAccountGrant grant=sessions.liveGrant(context.session(),account,current).orElseThrow(AuthenticationFailure::new);
            T result=command.apply(new SessionAccess.Context(context.session(),context.owner(),grant,current));
            Instant completed=clock.instant();
            if(!jwt.getExpiresAt().isAfter(completed) || !context.session().activeAt(completed))throw new AuthenticationFailure();
            sessions.touch(context.session(),sessions.liveGrant(context.session(),account,completed).orElseThrow(AuthenticationFailure::new),completed);
            return result;
        };
        List<UUID> additional=targetFences.values().stream().filter(Objects::nonNull).distinct().toList();
        UUID sid=UUID.fromString(jwt.getClaimAsString("sid")),subject=UUID.fromString(jwt.getSubject());
        return additional.isEmpty()?access.execute(sid,subject,work):access.executeForGroups(sid,subject,additional,work);
    }
    private UUID targetGroup(UUID account){List<UUID> rows=jdbc.query("SELECT account_group_id FROM account_group_member WHERE account_id=? AND status='LINKED'",(rs,n)->id(rs,"account_group_id"),bytes(account));return rows.isEmpty()?null:rows.getFirst();}
    private void personal(UUID account){if(jdbc.queryForList("SELECT a.id FROM user_account a JOIN users u ON u.id=a.user_id WHERE a.id=? AND a.type='PERSONAL' AND a.status='ACTIVE' AND u.status='ACTIVE' FOR UPDATE",bytes(account)).isEmpty())throw PersonalGroupAccess.denied();}
    private void lockGroup(UUID group,boolean write,Instant now){if(jdbc.queryForList("SELECT id FROM iam_group WHERE id=? AND workspace_context='INDIVIDUAL' AND "+(write?"status='ACTIVE'":"(status='ACTIVE' OR(status='CLOSING' AND purge_after>?))")+" FOR UPDATE",write?new Object[]{bytes(group)}:new Object[]{bytes(group),Timestamp.from(now)}).isEmpty())throw PersonalGroupAccess.denied();}
    private GroupView group(UUID group,UUID account){List<GroupView> rows=jdbc.query("SELECT * FROM iam_group WHERE id=? AND workspace_context='INDIVIDUAL'",(rs,n)->view(rs,account),bytes(group));if(rows.size()!=1)throw PersonalGroupAccess.denied();return rows.getFirst();}
    private GroupView view(java.sql.ResultSet rs,UUID account)throws java.sql.SQLException{return new GroupView(id(rs,"id"),rs.getString("name"),id(rs,"created_by_account_id"),rs.getString("status"),rs.getLong("version"),rs.getTimestamp("purge_after")==null?null:rs.getTimestamp("purge_after").toInstant(),id(rs,"created_by_account_id").equals(account));}
    private Invitation invitation(UUID identity){List<Invitation> rows=jdbc.query("SELECT * FROM personal_group_invitation WHERE id=?",(rs,n)->mapInvitation(rs,n),bytes(identity));if(rows.size()!=1)throw PersonalGroupAccess.denied();return rows.getFirst();}
    private Invitation mapInvitation(java.sql.ResultSet rs,int row)throws java.sql.SQLException{return new Invitation(id(rs,"id"),id(rs,"group_id"),id(rs,"sender_account_id"),id(rs,"recipient_account_id"),rs.getString("status"),rs.getLong("version"),rs.getTimestamp("created_at").toInstant(),rs.getTimestamp("expires_at").toInstant());}
    private void changed(SessionAccess.Context context,UUID actor,UUID group,String event,boolean bump,Instant deadline,boolean notifyMembers){
        if(bump)jdbc.update("UPDATE iam_group SET version=version+1,updated_at=? WHERE id=?",Timestamp.from(context.now()),bytes(group));
        GroupView current=group(group,actor);UUID eventId=UUID.randomUUID();Timestamp now=Timestamp.from(context.now());
        jdbc.update("INSERT INTO personal_group_audit(id,group_id,account_id,session_id,event_type,group_version,occurred_at) VALUES(?,?,?,?,?,?,?)",bytes(UUID.randomUUID()),bytes(group),bytes(actor),bytes(context.session().id()),event,current.version(),now);
        String payload="{\"eventId\":\"%s\",\"eventType\":\"%s\",\"sourceService\":\"auth-service\",\"schemaVersion\":1,\"aggregateType\":\"PERSONAL_GROUP\",\"aggregateId\":\"%s\",\"aggregateVersion\":%d,\"groupId\":\"%s\",\"ownerAccountId\":\"%s\",\"actorUserId\":\"%s\",\"sessionId\":\"%s\",\"workspaceContext\":\"INDIVIDUAL\",\"deadline\":%s,\"occurredAt\":\"%s\"}".formatted(eventId,event,group,current.version(),group,current.ownerAccountId(),context.owner().userId(),context.session().id(),deadline==null?"null":"\""+deadline+"\"",context.now());
        jdbc.update("INSERT INTO outbox_event(id,aggregate_type,aggregate_id,aggregate_version,event_type,payload,status,attempts,created_at,available_at) VALUES(?,'PERSONAL_GROUP',?,?,?,?,'PENDING',0,?,?)",bytes(eventId),bytes(group),current.version(),event,payload,now,now);
        if(notifyMembers)jdbc.update("INSERT INTO account_security_notice(id,user_id,account_id,code,reason,deadline,created_at,available_at) SELECT UUID_TO_BIN(UUID()),a.user_id,a.id,?,?,?, ?,? FROM personal_group_member m JOIN user_account a ON a.id=m.account_id WHERE m.group_id=? AND m.status='ACTIVE'",event,deadline==null?"A personal collaboration group changed.":"This group is scheduled for deletion. Copy content you need before the stated deadline.",deadline==null?null:Timestamp.from(deadline),now,now,bytes(group));
    }
    private void notice(UUID account,String code,String reason,Instant deadline,Instant now){jdbc.update("INSERT INTO account_security_notice(id,user_id,account_id,code,reason,deadline,created_at,available_at) SELECT UUID_TO_BIN(UUID()),user_id,id,?,?,?,?,? FROM user_account WHERE id=?",code,reason,deadline==null?null:Timestamp.from(deadline),Timestamp.from(now),Timestamp.from(now),bytes(account));}
    private static void owner(PersonalGroupAccess.Membership membership){if(!membership.owner())throw PersonalGroupAccess.denied();}
    private static void bounded(int limit){if(limit<1 || limit>100)throw bad();}
    private static String hash(String input){try{return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8)));}catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}}
    private static UUID uuid(byte[] value){java.nio.ByteBuffer buffer=java.nio.ByteBuffer.wrap(value);return new UUID(buffer.getLong(),buffer.getLong());}
    private static UUID id(java.sql.ResultSet rows,String column)throws java.sql.SQLException{return uuid(rows.getBytes(column));}
    private static ResponseStatusException bad(){return new ResponseStatusException(HttpStatus.BAD_REQUEST,"INVALID_PERSONAL_GROUP_COMMAND");}
    private static ResponseStatusException conflict(){return new ResponseStatusException(HttpStatus.CONFLICT,"PERSONAL_GROUP_CONFLICT");}
}
