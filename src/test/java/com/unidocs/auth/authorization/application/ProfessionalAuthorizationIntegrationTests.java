package com.unidocs.auth.authorization.application;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.domain.UserSession;
import com.unidocs.auth.session.persistence.SessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Transactional;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** SQL/catalog/scope tests with rollback-only identities; these are not real-session UAT evidence. */
@SpringBootTest
@Transactional
class ProfessionalAuthorizationIntegrationTests extends MySqlIntegrationTest {
    @Autowired ProfessionalAuthorizationService service;
    @Autowired JdbcTemplate jdbc;
    @MockitoBean SessionRepository sessions;
    @org.springframework.test.context.bean.override.mockito.MockitoSpyBean java.time.Clock clock;
    private UUID org,creator,account,user,membership,department,team;
    private Instant now;
    private SessionAccess.Context context;
    @BeforeEach void fixture() {
        now=Instant.now();creator=actor("PERSONAL",null,UUID.randomUUID());org=UUID.randomUUID();user=UUID.randomUUID();
        jdbc.update("INSERT INTO organization(id,name,slug,type,status,authorization_version,created_by_account_id,creation_request_id,creation_fingerprint,created_at,updated_at) VALUES(?,'Professional',?,'COMPANY','ACTIVE',1,?,?,REPEAT('a',64),?,?)",
                bytes(org),"org-"+org,bytes(creator),bytes(UUID.randomUUID()),time(now),time(now));
        jdbc.update("INSERT INTO organization_auth_policy VALUES(?,?,'PASSWORD',NULL,TRUE,FALSE,FALSE,?,?)",bytes(UUID.randomUUID()),bytes(org),time(now),time(now));
        account=actor("COMPANY",org,user);membership=member(account);department=group(null,"DEPARTMENT");team=group(department,"TEAM");
        assignGroup(account,membership,department);assignGroup(account,membership,team);
        UUID sid=UUID.randomUUID();
        UserSession session=new UserSession(sid,UUID.randomUUID(),account,"ACTIVE",now,now,now.plusSeconds(600),null);
        SessionAccountGrant grant=new SessionAccountGrant(sid,account,"ACTIVE","LOGIN",1,now.plusSeconds(600),now.plusSeconds(600));
        context=new SessionAccess.Context(session,new SessionRepository.Owner(user,"Employee",account),grant,now);
        when(sessions.liveGrant(eq(session),eq(account),any())).thenReturn(Optional.of(grant));
    }
    @Test void employeeUsesCurrentProfessionalCategoryAndExactGroupMembership() {
        assertThat(service.require(context,account,org,team,"document-service","file.read").categoryKey()).isEqualTo("ORGANIZATION");
        UUID unrelated=group(null,"TEAM");
        assertThatThrownBy(()->service.require(context,account,org,unrelated,"document-service","file.read")).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void organizationAndDepartmentDeniesBeatAnActiveTeamResponsibility() {
        responsibility(account,membership,team,"TEAM_ADMIN");
        assertThat(service.require(context,account,org,team,"document-service","file.read").reasonCode()).isEqualTo("ALLOWED");
        UUID restriction=deny(null,"file.read");
        assertThatThrownBy(()->service.require(context,account,org,team,"document-service","file.read")).isInstanceOf(OperationAuthorizationFailure.class);
        jdbc.update("UPDATE iam_professional_restriction SET status='REVOKED' WHERE id=?",bytes(restriction));
        deny(department,"file.read");
        assertThatThrownBy(()->service.require(context,account,org,team,"document-service","file.read")).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void categoryRemovalChangesTheSameSessionsNextSharingRequestOnly() {
        assertThat(service.require(context,account,org,team,"document-service","file.share.view").reasonCode()).isEqualTo("ALLOWED");
        jdbc.update("DELETE ra FROM iam_role_authority ra JOIN iam_stakeholder_role_binding b ON b.role_id=ra.role_id AND b.category_key='ORGANIZATION' JOIN iam_authority a ON a.id=ra.authority_id AND a.authority_key='file.share' AND a.service_id='document-service'");
        jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
        assertThatThrownBy(()->service.require(context,account,org,team,"document-service","file.share.view")).isInstanceOf(OperationAuthorizationFailure.class);
        assertThat(service.require(context,account,org,team,"document-service","file.read").reasonCode()).isEqualTo("ALLOWED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_role_authority ra JOIN iam_stakeholder_role_binding b ON b.role_id=ra.role_id AND b.category_key='INDIVIDUAL' JOIN iam_authority a ON a.id=ra.authority_id AND a.authority_key='file.share' AND a.service_id='document-service'",Integer.class)).isEqualTo(1);
    }
    @Test void platformDenyAndRevokedOrganizationMembershipFailClosed() {
        jdbc.update("INSERT INTO iam_operation_restriction(id,operation_id,category_key,account_id,status,version,valid_from) SELECT ?,id,'ORGANIZATION',?,'ACTIVE',1,? FROM iam_operation WHERE service_id='document-service' AND operation_key='file.read'",bytes(UUID.randomUUID()),bytes(account),time(now.minusSeconds(30)));
        assertThatThrownBy(()->service.require(context,account,org,team,"document-service","file.read")).isInstanceOf(OperationAuthorizationFailure.class);
        jdbc.update("UPDATE organization_membership SET status='REVOKED',revoked_at=?,revoked_by=? WHERE id=?",time(now),bytes(creator),bytes(membership));
        assertThatThrownBy(()->service.require(context,account,org,team,"document-service","file.download")).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void departmentAdministratorCannotAssignAnEmployeeFromAnotherDepartment() {
        responsibility(account,membership,department,"DEPARTMENT_ADMIN");
        UUID target=actor("COMPANY",org,UUID.randomUUID());UUID targetMember=member(target);
        assertThat(service.require(context,account,org,team,"auth-service","organization.group.assign").reasonCode()).isEqualTo("ALLOWED");
        assertThatThrownBy(()->service.assignmentRecipient(context,account,org,team,target)).isInstanceOf(OperationAuthorizationFailure.class);
        assignGroup(target,targetMember,department);
        assertThatCode(()->service.assignmentRecipient(context,account,org,team,target)).doesNotThrowAnyException();
    }
    @Test void teamResponsibilityDoesNotPermitMembershipAssignment() {
        responsibility(account,membership,team,"TEAM_ADMIN");
        assertThatThrownBy(()->service.require(context,account,org,team,"auth-service","organization.group.assign")).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void exactInvitationsDoNotCreateTeamMembershipOrDefeatUpstreamDenial() {
        UUID unrelated=group(null,"TEAM");
        assertThatThrownBy(()->service.require(context,account,org,unrelated,"document-service","file.read")).isInstanceOf(OperationAuthorizationFailure.class);
        assertThat(service.require(context,account,org,unrelated,"document-service","file.read",true).reasonCode()).isEqualTo("ALLOWED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM group_membership WHERE group_id=? AND account_id=?",Integer.class,bytes(unrelated),bytes(account))).isZero();
        deny(unrelated,"file.read");
        assertThatThrownBy(()->service.require(context,account,org,unrelated,"document-service","file.read",true)).isInstanceOf(OperationAuthorizationFailure.class);
        assertThatThrownBy(()->service.require(context,account,org,unrelated,"auth-service","organization.group.assign",true)).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void recipientCheckAllowsExistingOrganizationEmployeeWithoutAssigningTeamMembership() {
        UUID recipientUser=UUID.randomUUID();UUID recipient=actor("COMPANY",org,recipientUser);member(recipient);
        UUID accountGroup=UUID.randomUUID();
        jdbc.update("INSERT INTO account_group(id,user_id,status,created_at,updated_at) VALUES(?,?,'ACTIVE',?,?)",bytes(accountGroup),bytes(recipientUser),time(now),time(now));
        jdbc.update("INSERT INTO account_group_member(account_id,account_group_id,status,link_method,linked_by_account_id,linked_at) VALUES(?,?,'LINKED','REGISTRATION',?,?)",bytes(recipient),bytes(accountGroup),bytes(recipient),time(now));
        assertThat(service.recipient(org,team,recipient,"EDIT")).isEqualTo(recipientUser);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM group_membership WHERE group_id=? AND account_id=?",Integer.class,bytes(team),bytes(recipient))).isZero();
        UUID restriction=deny(team,"file.collaborative.edit");
        jdbc.update("UPDATE iam_professional_restriction SET account_id=? WHERE id=?",bytes(recipient),bytes(restriction));
        assertThat(service.recipient(org,team,recipient,"VIEW")).isEqualTo(recipientUser);
        assertThatThrownBy(()->service.recipient(org,team,recipient,"EDIT")).isInstanceOf(OperationAuthorizationFailure.class);
        assertThatThrownBy(()->service.recipient(org,team,creator,"VIEW")).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void expiredResponsibilityOrGroupMembershipCannotAuthorize() {
        UUID assignment=responsibility(account,membership,team,"TEAM_ADMIN");
        assertThat(service.require(context,account,org,team,"auth-service","team.access.update").reasonCode()).isEqualTo("ALLOWED");
        jdbc.update("UPDATE iam_professional_assignment SET valid_until=? WHERE id=?",time(now.minusSeconds(1)),bytes(assignment));
        assertThatThrownBy(()->service.require(context,account,org,team,"auth-service","team.access.update")).isInstanceOf(OperationAuthorizationFailure.class);
        jdbc.update("UPDATE group_membership SET membership_type='TEMPORARY',valid_until=? WHERE organization_id=? AND group_id=? AND account_id=?",time(now.minusSeconds(1)),bytes(org),bytes(team),bytes(account));
        assertThatThrownBy(()->service.require(context,account,org,team,"document-service","file.read")).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void responsibilityExpiringDuringSqlWaitInvalidatesTheComputedAllow() {
        UUID assignment=responsibility(account,membership,team,"TEAM_ADMIN");
        jdbc.update("UPDATE iam_professional_assignment SET valid_until=? WHERE id=?",time(now.plusSeconds(5)),bytes(assignment));
        doReturn(now,now,now.plusSeconds(10)).when(clock).instant();
        assertThatThrownBy(()->service.require(context,account,org,team,"auth-service","team.access.update")).isInstanceOf(OperationAuthorizationFailure.class);
    }
    @Test void anyOfCannotSplitWitnessesAndReturnsOnlyCommonWitnessesToDocument() {
        byte[] policy=jdbc.queryForObject("SELECT p.id FROM iam_operation_policy p JOIN iam_operation o ON o.id=p.operation_id WHERE o.service_id='document-service' AND o.operation_key='file.share'",byte[].class);
        jdbc.update("DELETE FROM iam_policy_authority WHERE policy_id=?",policy);
        jdbc.update("INSERT INTO iam_policy_authority(policy_id,service_id,authority_id,authority_slot) SELECT ?,'document-service',id,1 FROM iam_authority WHERE service_id='document-service' AND authority_key='file.read'",policy);
        jdbc.update("INSERT INTO iam_policy_authority(policy_id,service_id,authority_id,authority_slot) SELECT ?,'document-service',id,2 FROM iam_authority WHERE service_id='document-service' AND authority_key='file.download'",policy);
        jdbc.update("UPDATE iam_operation_policy SET match_mode='ANY_OF',version=version+1 WHERE id=?",policy);
        jdbc.update("DELETE ra FROM iam_role_authority ra JOIN iam_stakeholder_role_binding b ON b.role_id=ra.role_id AND b.category_key='ORGANIZATION' JOIN iam_authority a ON a.id=ra.authority_id AND a.authority_key='file.download' AND a.service_id='document-service'");
        jdbc.update("DELETE ra FROM iam_role_authority ra JOIN iam_context_member_role_binding b ON b.role_id=ra.role_id AND b.category_key='ORGANIZATION' JOIN iam_authority a ON a.id=ra.authority_id AND a.authority_key='file.read' AND a.service_id='document-service'");
        jdbc.update("UPDATE iam_policy_revision SET revision=revision+1 WHERE id='GLOBAL'");
        assertThatThrownBy(()->service.require(context,account,org,team,"document-service","file.share")).isInstanceOf(OperationAuthorizationFailure.class);
        jdbc.update("INSERT INTO iam_role_authority(role_id,authority_id) SELECT b.role_id,a.id FROM iam_stakeholder_role_binding b CROSS JOIN iam_authority a WHERE b.category_key='ORGANIZATION' AND a.authority_key='file.download' AND a.service_id='document-service'");
        assertThat(service.require(context,account,org,team,"document-service","file.share").categoryAuthorities()).containsExactly("file.download");
    }
    @Test void personalAndCrossOrganizationAccountsCannotBeReclassifiedByMembershipOrGrant() {
        assertThatThrownBy(()->service.require(context,creator,org,null,"document-service","file.read")).isInstanceOf(OperationAuthorizationFailure.class);
        UUID other=UUID.randomUUID();
        assertThatThrownBy(()->service.require(context,account,other,null,"document-service","file.read")).isInstanceOf(OperationAuthorizationFailure.class);
    }
    private UUID actor(String type,UUID organization,UUID actorUser) {
        UUID id=UUID.randomUUID();jdbc.update("INSERT INTO users(id,display_name,status,created_at,updated_at) VALUES(?,'Synthetic','ACTIVE',?,?)",bytes(actorUser),time(now),time(now));
        jdbc.update("INSERT INTO user_account(id,user_id,organization_id,type,display_name,status,created_at,updated_at) VALUES(?,?,?,?,'Synthetic','ACTIVE',?,?)",bytes(id),bytes(actorUser),organization==null?null:bytes(organization),type,time(now),time(now));return id;
    }
    private UUID member(UUID actor) {
        UUID id=UUID.randomUUID();jdbc.update("INSERT INTO organization_membership(id,organization_id,account_id,role,status,official_email,version,joined_at,created_at,updated_at) VALUES(?,?,?,'MEMBER','ACTIVE',NULL,1,?,?,?)",bytes(id),bytes(org),bytes(actor),time(now),time(now),time(now));return id;
    }
    private UUID group(UUID parent,String type) {
        UUID id=UUID.randomUUID();jdbc.update("INSERT INTO iam_group(id,organization_id,parent_group_id,name,type,status,version,created_by_account_id,creation_request_id,creation_fingerprint,created_at,updated_at) VALUES(?,?,?,'Group',?,'ACTIVE',1,?,?,REPEAT('b',64),?,?)",bytes(id),bytes(org),parent==null?null:bytes(parent),type,bytes(creator),bytes(UUID.randomUUID()),time(now),time(now));return id;
    }
    private void assignGroup(UUID actor,UUID anchor,UUID group) {
        jdbc.update("INSERT INTO group_membership(id,organization_id,group_id,account_id,organization_membership_id,role,membership_type,source,status,valid_from,version,assigned_by_account_id,assignment_request_id,assignment_fingerprint,created_at,updated_at) VALUES(?,?,?,?,?,'MEMBER','PERMANENT','ORGANIZATION_ASSIGNMENT','ACTIVE',?,1,?,?,REPEAT('c',64),?,?)",bytes(UUID.randomUUID()),bytes(org),bytes(group),bytes(actor),bytes(anchor),time(now.minusSeconds(60)),bytes(creator),bytes(UUID.randomUUID()),time(now),time(now));
    }
    private UUID responsibility(UUID actor,UUID anchor,UUID group,String role) {
        UUID id=UUID.randomUUID();jdbc.update("INSERT INTO iam_professional_assignment(id,organization_id,membership_id,account_id,group_id,role_id,status,valid_from) SELECT ?,?,?,?,?,id,'ACTIVE',? FROM iam_role WHERE role_key=?",bytes(id),bytes(org),bytes(anchor),bytes(actor),group==null?null:bytes(group),time(now.minusSeconds(60)),role);return id;
    }
    private UUID deny(UUID group,String operation) {
        UUID id=UUID.randomUUID();jdbc.update("INSERT INTO iam_professional_restriction(id,organization_id,group_id,operation_id,status,valid_from) SELECT ?,?,?,id,'ACTIVE',? FROM iam_operation WHERE operation_key=? AND service_id='document-service'",bytes(id),bytes(org),group==null?null:bytes(group),time(now.minusSeconds(30)),operation);return id;
    }
    private static Timestamp time(Instant value) { return Timestamp.from(value); }
}
