package com.unidocs.auth.outbox.persistence;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Repository
public class OutboxRepository {
    private final JdbcTemplate jdbc;
    public OutboxRepository(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    public void professionalReconciled(UUID organization,long version,UUID sourceAccount,UUID account,
            UUID sourceMembership,UUID membership,Instant now) {
        UUID event=UUID.randomUUID();
        String payload="""
                {"eventId":"%s","eventType":"PROFESSIONAL_ACCOUNT_RECONCILED","aggregateType":"ORGANIZATION",
                 "aggregateId":"%s","aggregateVersion":%d,"organizationId":"%s","sourceAccountId":"%s",
                 "accountId":"%s","sourceMembershipId":"%s","membershipId":"%s","occurredAt":"%s"}
                """.formatted(event,organization,version,organization,sourceAccount,account,sourceMembership,membership,now);
        enqueue(event,"ORGANIZATION",organization,version,"PROFESSIONAL_ACCOUNT_RECONCILED",payload,now);
    }
    public void groupJoinChanged(com.unidocs.auth.group.domain.GroupJoinRequest request,String eventType,Instant now) {
        UUID event=UUID.randomUUID();
        String payload="""
            {"eventId":"%s","eventType":"%s","aggregateType":"GROUP_JOIN_REQUEST","aggregateId":"%s",
             "aggregateVersion":%d,"organizationId":"%s","groupId":"%s","accountId":"%s",
             "organizationMembershipId":"%s","status":"%s","membershipId":%s,"occurredAt":"%s"}
            """.formatted(event,eventType,request.id(),request.version(),request.organizationId(),request.groupId(),request.accountId(),
                request.organizationMembershipId(),request.status(),json(request.membershipId()),now);
        enqueue(event,"GROUP_JOIN_REQUEST",request.id(),request.version(),eventType,payload,now);
    }
    public void groupMembershipChanged(com.unidocs.auth.group.domain.GroupMembership membership,
            long organizationVersion, String eventType, Instant now) {
        groupMembershipChanged(membership,organizationVersion,eventType,now,true);
    }
    public void groupMembershipChanged(com.unidocs.auth.group.domain.GroupMembership membership,
            long organizationVersion,String eventType,Instant now,boolean emitOrganization) {
        UUID event = UUID.randomUUID();
        String payload = """
            {"eventId":"%s","eventType":"%s","aggregateType":"GROUP_MEMBERSHIP","aggregateId":"%s",
             "aggregateVersion":%d,"organizationId":"%s","organizationVersion":%d,"groupId":"%s",
             "accountId":"%s","organizationMembershipId":"%s","source":"%s","sourceReference":%s,"validFrom":"%s","validUntil":%s,"occurredAt":"%s"}
            """.formatted(event,eventType,membership.id(),membership.version(),membership.organizationId(),organizationVersion,
                membership.groupId(),membership.accountId(),membership.organizationMembershipId(),membership.source(),json(membership.sourceReference()),membership.validFrom(),json(membership.validUntil()),now);
        enqueue(event,"GROUP_MEMBERSHIP",membership.id(),membership.version(),eventType,payload,now);
        markSpiceDbOrganizationSyncRequired(membership.organizationId(), organizationVersion, now);
        if(emitOrganization) lifecycle("ORGANIZATION",membership.organizationId(),organizationVersion,"ORGANIZATION_GROUP_MEMBERSHIP_CHANGED",
                membership.accountId(),membership.organizationId(),null,now);
    }
    public void groupCreated(UUID group, UUID organization, UUID parent, Instant now) {
        UUID event = UUID.randomUUID();
        String parentJson = parent == null ? "null" : "\"" + parent + "\"";
        String payload = """
            {"eventId":"%s","eventType":"GROUP_CREATED","aggregateType":"GROUP",
             "aggregateId":"%s","aggregateVersion":1,"organizationId":"%s","parentGroupId":%s,"occurredAt":"%s"}
            """.formatted(event, group, organization, parentJson, now);
        enqueue(event, "GROUP", group, 1, "GROUP_CREATED", payload, now);
        Long organizationVersion=jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(organization));
        if(organizationVersion!=null) markSpiceDbOrganizationSyncRequired(organization,organizationVersion,now);
    }
    public void accountProvisioned(UUID account,UUID organization,UUID membership,Instant now) {
        UUID event=UUID.randomUUID();
        String payload="""
            {"eventId":"%s","eventType":"ORGANIZATION_ACCOUNT_PROVISIONED","aggregateType":"USER_ACCOUNT",
             "aggregateId":"%s","aggregateVersion":1,"organizationId":"%s","membershipId":"%s","occurredAt":"%s"}
            """.formatted(event,account,organization,membership,now);
        enqueue(event,"USER_ACCOUNT",account,1,"ORGANIZATION_ACCOUNT_PROVISIONED",payload,now);
    }
    public void invitationChanged(UUID invitation, UUID organization, long version, String status, Instant now) {
        com.unidocs.auth.organization.domain.OrganizationInvitation.Status.valueOf(status);
        UUID event=UUID.randomUUID();
        String payload="""
            {"eventId":"%s","eventType":"ORGANIZATION_INVITATION_CHANGED","aggregateType":"ORG_INVITATION",
             "aggregateId":"%s","aggregateVersion":%d,"organizationId":"%s","status":"%s","occurredAt":"%s"}
            """.formatted(event,invitation,version,organization,status,now);
        enqueue(event,"ORG_INVITATION",invitation,version,"ORGANIZATION_INVITATION_CHANGED",payload,now);
    }
    public void membershipActivated(UUID organization, UUID membership, UUID account, UUID invitation, long version, Instant now) {
        UUID event=UUID.randomUUID();
        String payload="""
            {"eventId":"%s","eventType":"ORGANIZATION_MEMBERSHIP_ACTIVATED","aggregateType":"ORGANIZATION",
             "aggregateId":"%s","aggregateVersion":%d,"membershipId":"%s","membershipVersion":1,
             "accountId":"%s","invitationId":"%s","occurredAt":"%s"}
            """.formatted(event,organization,version,membership,account,invitation,now);
        enqueue(event,"ORGANIZATION",organization,version,"ORGANIZATION_MEMBERSHIP_ACTIVATED",payload,now);
    }
    public void lifecycle(String type,UUID aggregate,long version,String eventType,UUID account,UUID organization,Instant deadline,Instant now) {
        lifecycleSubject(type,aggregate,version,eventType,account,organization,null,null,deadline,now);
    }
    public void lifecycleSubject(String type,UUID aggregate,long version,String eventType,UUID account,UUID organization,UUID user,UUID restriction,Instant deadline,Instant now) {
        UUID event=UUID.randomUUID();
        String payload="""
            {"eventId":"%s","eventType":"%s","aggregateType":"%s","aggregateId":"%s","aggregateVersion":%d,
             "accountId":%s,"organizationId":%s,"userId":%s,"restrictionId":%s,"deadline":%s,"occurredAt":"%s"}
            """.formatted(event,eventType,type,aggregate,version,json(account),json(organization),json(user),json(restriction),json(deadline),now);
        enqueue(event,type,aggregate,version,eventType,payload,now);
    }
    public void studentWorkspace(UUID semester,UUID organization,UUID workspace,UUID account,UUID user,Instant startsAt,Instant endsAt,Instant now) {
        UUID event=UUID.randomUUID();
        String payload="""
            {"eventId":"%s","eventType":"STUDENT_SEMESTER_WORKSPACE_REQUESTED","aggregateType":"ACADEMIC_SEMESTER","aggregateId":"%s","aggregateVersion":1,
            "organizationId":"%s","workspaceId":"%s","accountId":"%s","userId":"%s","startsAt":"%s","endsAt":"%s","occurredAt":"%s"}
            """.formatted(event,semester,organization,workspace,account,user,startsAt,endsAt,now);
        enqueue(event,"ACADEMIC_SEMESTER",semester,1,"STUDENT_SEMESTER_WORKSPACE_REQUESTED",payload,now);
    }
    private static String json(Object value) { return value==null?"null":"\""+value+"\""; }
    private void enqueue(UUID event,String type,UUID aggregate,long version,String eventType,String payload,Instant now) {
        jdbc.update("""
            INSERT INTO outbox_event(id,aggregate_type,aggregate_id,aggregate_version,event_type,payload,status,attempts,created_at,available_at)
            VALUES(?,?,?,?,?,?,'PENDING',0,?,?)
            """,bytes(event),type,bytes(aggregate),version,eventType,payload,Timestamp.from(now),Timestamp.from(now));
        if ("ORGANIZATION".equals(type)) markSpiceDbOrganizationSyncRequired(aggregate, version, now);
        if ("IAM_POLICY".equals(type)) markAllSpiceDbOrganizationSyncsRequired(now);
    }
    public void organizationCreated(UUID organization, UUID membership, UUID account, Instant now) {
        UUID event=UUID.randomUUID();
        String payload="""
            {"eventId":"%s","eventType":"ORGANIZATION_CREATED","aggregateType":"ORGANIZATION","aggregateId":"%s","aggregateVersion":1,
             "membershipId":"%s","accountId":"%s","membershipVersion":1,"occurredAt":"%s"}
            """.formatted(event,organization,membership,account,now);
        jdbc.update("""
            INSERT INTO outbox_event(id,aggregate_type,aggregate_id,aggregate_version,event_type,payload,status,attempts,created_at,available_at)
            VALUES(?,'ORGANIZATION',?,1,'ORGANIZATION_CREATED',?,'PENDING',0,?,?)
            """,bytes(event),bytes(organization),payload,Timestamp.from(now),Timestamp.from(now));
        markSpiceDbOrganizationSyncRequired(organization, 1, now);
    }

    private void markSpiceDbOrganizationSyncRequired(UUID organization, long authorizationVersion, Instant now) {
        jdbc.update("""
            INSERT INTO spicedb_organization_sync_state(organization_id,required_revision,applied_revision,required_source_version,
                applied_source_version,sync_status,available_at,created_at,updated_at)
            VALUES(?,1,0,?,0,'PENDING',?,?,?)
            ON DUPLICATE KEY UPDATE
                required_revision=required_revision+1,
                required_source_version=GREATEST(required_source_version,VALUES(required_source_version)),
                sync_status='PENDING',last_error_code=NULL,updated_at=VALUES(updated_at)
            """,bytes(organization),authorizationVersion,Timestamp.from(now),Timestamp.from(now),Timestamp.from(now));
    }

    private void markAllSpiceDbOrganizationSyncsRequired(Instant now) {
        jdbc.update("""
            INSERT INTO spicedb_organization_sync_state(organization_id,required_revision,applied_revision,required_source_version,
                applied_source_version,sync_status,available_at,created_at,updated_at)
            SELECT id,1,0,authorization_version,0,'PENDING',?,?,? FROM organization
            ON DUPLICATE KEY UPDATE required_revision=required_revision+1,
                required_source_version=GREATEST(required_source_version,VALUES(required_source_version)),
                sync_status='PENDING',available_at=VALUES(available_at),last_error_code=NULL,updated_at=VALUES(updated_at)
            """,Timestamp.from(now),Timestamp.from(now),Timestamp.from(now));
    }
}
