package com.unidocs.auth.group.personal;

import java.time.*;
import java.sql.Timestamp;
import java.util.*;
import java.util.function.Function;
import com.unidocs.auth.MySqlIntegrationTest;
import com.unidocs.auth.authorization.application.OperationAuthorizationService;
import com.unidocs.auth.session.application.SessionAccess;
import com.unidocs.auth.session.domain.*;
import com.unidocs.auth.session.persistence.SessionRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest(properties="auth.personal-groups.test-notice-seconds=2")
class PersonalGroupIntegrationTests extends MySqlIntegrationTest {
    @Autowired PersonalGroupService service;
    @Autowired PersonalGroupClosureService closures;
    @Autowired PersonalAccountDeparture departure;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager transactionManager;
    @MockitoBean SessionAccess access;
    @MockitoBean SessionRepository sessions;
    @MockitoBean OperationAuthorizationService policy;
    private UUID owner,member,stranger;
    private final Map<UUID,UUID> users=new HashMap<>();
    private Instant now;
    @BeforeEach void fixtures(){
        now=Instant.now();owner=actor("Owner","PERSONAL");member=actor("Member","PERSONAL");stranger=actor("Stranger","PERSONAL");
        when(access.execute(any(),any(),any())).thenAnswer(invocation->{
            UUID subject=invocation.getArgument(1);UUID sid=invocation.getArgument(0);
            SessionAccountGrant grant=new SessionAccountGrant(sid,subject,"ACTIVE","LOGIN",1,now.plusSeconds(600),now.plusSeconds(600));
            SessionAccess.Context context=new SessionAccess.Context(new UserSession(sid,UUID.randomUUID(),subject,"ACTIVE",now,now,now.plusSeconds(600),null),new SessionRepository.Owner(users.get(subject),"Actor",subject),grant,now);
            Function<SessionAccess.Context,Object> command=invocation.getArgument(2);
            return new TransactionTemplate(transactionManager).execute(status->command.apply(context));
        });
        when(sessions.liveGrant(any(),any(),any())).thenAnswer(invocation->Optional.of(new SessionAccountGrant(((UserSession)invocation.getArgument(0)).id(),invocation.getArgument(1),"ACTIVE","LOGIN",1,now.plusSeconds(600),now.plusSeconds(600))));
    }
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    @Test void invitationsCreateExactMembershipWithoutPublicDiscovery(){
        Jwt ownerJwt=as(owner);PersonalGroupService.GroupView group=service.create(ownerJwt,owner,"Study together",UUID.randomUUID());
        Jwt strangerJwt=as(stranger);
        assertThat(service.list(strangerJwt,stranger,null,10).items()).isEmpty();
        assertThatThrownBy(()->service.get(strangerJwt,stranger,group.id())).isInstanceOf(ResponseStatusException.class);
        ownerJwt=as(owner);PersonalGroupService.Invitation invitation=service.invite(ownerJwt,owner,group.id(),member,UUID.randomUUID());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM personal_group_member WHERE group_id=?",Integer.class,bytes(group.id()))).isEqualTo(1);
        Jwt memberJwt=as(member);
        assertThat(service.invitations(memberJwt,member,null,10).items()).hasSize(1);
        assertThat(service.respond(memberJwt,member,invitation.id(),true).status()).isEqualTo("ACCEPTED");
        assertThat(service.get(memberJwt,member,group.id()).owner()).isFalse();
        assertThatThrownBy(()->service.invite(memberJwt,member,group.id(),stranger,UUID.randomUUID())).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(()->service.scheduleDeletion(memberJwt,member,group.id())).isInstanceOf(ResponseStatusException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM organization_membership WHERE account_id=?",Integer.class,bytes(member))).isZero();
    }
    @Test void onlyOwnerCanPagePendingOutgoingInvitationsAndRevokedInvitationsDisappear(){
        PersonalGroupService.GroupView group=service.create(as(owner),owner,"Private invitations",UUID.randomUUID());
        PersonalGroupService.Invitation first=service.invite(as(owner),owner,group.id(),member,UUID.randomUUID());
        PersonalGroupService.Invitation second=service.invite(as(owner),owner,group.id(),stranger,UUID.randomUUID());
        PersonalGroupService.InvitationPage page=service.outgoing(as(owner),owner,group.id(),null,1);
        assertThat(page.items()).hasSize(1);assertThat(page.nextCursor()).isEqualTo(page.items().getFirst().id());
        PersonalGroupService.InvitationPage next=service.outgoing(as(owner),owner,group.id(),page.nextCursor(),1);
        assertThat(next.items()).hasSize(1);assertThat(next.nextCursor()).isNull();
        assertThat(next.items().getFirst().id()).isNotEqualTo(page.items().getFirst().id());
        service.respond(as(member),member,first.id(),true);
        assertThatThrownBy(()->service.outgoing(as(member),member,group.id(),null,10)).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(()->service.outgoing(as(stranger),stranger,group.id(),null,10)).isInstanceOf(ResponseStatusException.class);
        assertThat(service.outgoing(as(owner),owner,group.id(),null,10).items()).extracting(PersonalGroupService.Invitation::id).containsExactly(second.id());
        service.revoke(as(owner),owner,group.id(),second.id());
        assertThat(service.outgoing(as(owner),owner,group.id(),null,10).items()).isEmpty();
        assertThatThrownBy(()->service.outgoing(as(owner),owner,group.id(),null,0)).isInstanceOf(ResponseStatusException.class);
    }
    @Test void memberListingIsPagedAndNeverDiscoversAnotherGroupOrRevokedMember(){
        PersonalGroupService.GroupView group=service.create(as(owner),owner,"Member list",UUID.randomUUID());
        PersonalGroupService.Invitation invite=service.invite(as(owner),owner,group.id(),member,UUID.randomUUID());
        service.respond(as(member),member,invite.id(),true);
        PersonalGroupService.MemberPage page=service.members(as(member),member,group.id(),null,1);
        assertThat(page.items()).hasSize(1);assertThat(page.nextCursor()).isNotNull();
        PersonalGroupService.MemberPage next=service.members(as(owner),owner,group.id(),page.nextCursor(),1);
        assertThat(next.items()).hasSize(1);assertThat(next.nextCursor()).isNull();
        List<PersonalGroupService.Member> all=new ArrayList<>(page.items());all.addAll(next.items());
        assertThat(all).extracting(PersonalGroupService.Member::accountId).containsExactlyInAnyOrder(owner,member);
        assertThat(all.stream().filter(PersonalGroupService.Member::owner).toList()).extracting(PersonalGroupService.Member::accountId).containsExactly(owner);
        assertThatThrownBy(()->service.members(as(stranger),stranger,group.id(),null,10)).isInstanceOf(ResponseStatusException.class);
        service.remove(as(owner),owner,group.id(),member,false);
        assertThat(service.members(as(owner),owner,group.id(),null,10).items()).extracting(PersonalGroupService.Member::accountId).containsExactly(owner);
        assertThatThrownBy(()->service.members(as(member),member,group.id(),null,10)).isInstanceOf(ResponseStatusException.class);
    }
    @Test void wrongRecipientAndDeclinedInvitationCannotEstablishMembership(){
        Jwt ownerJwt=as(owner);PersonalGroupService.GroupView group=service.create(ownerJwt,owner,"Private",UUID.randomUUID());
        PersonalGroupService.Invitation invite=service.invite(ownerJwt,owner,group.id(),member,UUID.randomUUID());
        Jwt strangerJwt=as(stranger);
        assertThatThrownBy(()->service.respond(strangerJwt,stranger,invite.id(),true)).isInstanceOf(ResponseStatusException.class);
        Jwt memberJwt=as(member);assertThat(service.respond(memberJwt,member,invite.id(),false).status()).isEqualTo("DECLINED");
        assertThatThrownBy(()->service.respond(memberJwt,member,invite.id(),true)).isInstanceOf(ResponseStatusException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM personal_group_member WHERE group_id=? AND account_id=?",Integer.class,bytes(group.id()),bytes(member))).isZero();
    }
    @Test void revocationRemovesCurrentAccessAndOwnerCannotOrphanGroup(){
        Jwt ownerJwt=as(owner);PersonalGroupService.GroupView group=service.create(ownerJwt,owner,"Private",UUID.randomUUID());
        PersonalGroupService.Invitation invite=service.invite(ownerJwt,owner,group.id(),member,UUID.randomUUID());
        Jwt memberJwt=as(member);service.respond(memberJwt,member,invite.id(),true);
        ownerJwt=as(owner);
        assertThatThrownBy(()->service.remove(as(owner),owner,group.id(),owner,true)).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(409));
        service.remove(as(owner),owner,group.id(),member,false);
        assertThatThrownBy(()->service.get(as(member),member,group.id())).isInstanceOf(ResponseStatusException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM account_security_notice WHERE account_id=? AND code='PERSONAL_GROUP_ACCESS_REVOKED'",Integer.class,bytes(member))).isEqualTo(1);
    }
    @Test void deletionCapturesDeadlineNoticesOutboxAndClosesMutations(){
        Jwt ownerJwt=as(owner);PersonalGroupService.GroupView group=service.create(ownerJwt,owner,"Private",UUID.randomUUID());
        PersonalGroupService.Invitation invitation=service.invite(ownerJwt,owner,group.id(),member,UUID.randomUUID());
        service.respond(as(member),member,invitation.id(),true);
        PersonalGroupService.GroupView preparing=service.scheduleDeletion(as(owner),owner,group.id());
        assertThat(preparing.status()).isEqualTo("PREPARING");assertThat(preparing.purgeAfter()).isNull();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM account_security_notice WHERE code='PERSONAL_GROUP_DELETION_SCHEDULED' AND account_id IN (?,?)",Integer.class,bytes(owner),bytes(member))).isZero();
        PersonalGroupClosureService.Closure closing=closures.confirmNotices(worker("document-service",now.plusSeconds(600)),group.id(),preparing.version(),UUID.randomUUID());
        assertThat(closing.status()).isEqualTo("CLOSING");assertThat(closing.purgeAfter()).isBetween(now.plusSeconds(1),Instant.now().plusSeconds(3));
        assertThat(service.get(as(member),member,group.id()).id()).isEqualTo(group.id());
        assertThatThrownBy(()->service.invite(as(owner),owner,group.id(),stranger,UUID.randomUUID())).isInstanceOf(ResponseStatusException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM account_security_notice WHERE code='PERSONAL_GROUP_DELETION_SCHEDULED' AND account_id IN (?,?)",Integer.class,bytes(owner),bytes(member))).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE aggregate_id=? AND event_type='PERSONAL_GROUP_DELETION_SCHEDULED'",Integer.class,bytes(group.id()))).isEqualTo(1);
        jdbc.update("UPDATE iam_group SET purge_after=? WHERE id=?",Timestamp.from(now.minusSeconds(1)),bytes(group.id()));
        assertThatThrownBy(()->service.get(as(member),member,group.id())).isInstanceOf(ResponseStatusException.class);
    }
    @Test void creationAndInvitationRequestIdsAreRetrySafe(){
        UUID request=UUID.randomUUID();Jwt ownerJwt=as(owner);PersonalGroupService.GroupView first=service.create(ownerJwt,owner,"Private",request);
        assertThat(service.create(ownerJwt,owner,"Private",request).id()).isEqualTo(first.id());
        assertThatThrownBy(()->service.create(ownerJwt,owner,"Different",request)).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(409));
        UUID invitationRequest=UUID.randomUUID();PersonalGroupService.Invitation invite=service.invite(ownerJwt,owner,first.id(),member,invitationRequest);
        assertThat(service.invite(ownerJwt,owner,first.id(),member,invitationRequest)).isEqualTo(invite);
        assertThatThrownBy(()->service.invite(ownerJwt,owner,first.id(),stranger,invitationRequest)).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(409));
    }
    @Test void nonPersonalRecipientsAndDisabledAccountsAreRejected(){
        UUID employee=actor("Employee","PERSONAL");
        jdbc.update("UPDATE user_account SET status='DISABLED' WHERE id=?",bytes(employee));
        PersonalGroupService.GroupView group=service.create(as(owner),owner,"Private",UUID.randomUUID());
        assertThatThrownBy(()->service.invite(as(owner),owner,group.id(),employee,UUID.randomUUID())).isInstanceOf(ResponseStatusException.class);
    }
    @Test void documentWorkerReadsBoundedCurrentClosureIntentsWithoutDelegatedUserGrant(){
        PersonalGroupService.GroupView first=service.create(as(owner),owner,"Closing one",UUID.randomUUID());
        service.scheduleDeletion(as(owner),owner,first.id());
        PersonalGroupService.GroupView second=service.create(as(owner),owner,"Closing two",UUID.randomUUID());
        service.scheduleDeletion(as(owner),owner,second.id());
        org.springframework.security.core.Authentication worker=worker("document-service",now.plusSeconds(600));
        PersonalGroupClosureService.Page page=closures.closures(worker,null,1);
        assertThat(page.items()).hasSize(1);assertThat(page.nextCursor()).isNotNull();
        assertThat(page.items().getFirst().ownerAccountId()).isEqualTo(owner);
        assertThat(page.items().getFirst().ownerUserId()).isEqualTo(users.get(owner));
        assertThat(page.items().getFirst().status()).isEqualTo("PREPARING");
        assertThat(page.items().getFirst().noticeSeconds()).isEqualTo(2);
        assertThat(page.items().getFirst().purgeAfter()).isNull();
        assertThat(page.items().getFirst().purgeEligible()).isFalse();
        assertThat(page.items().getFirst().deletionRequestedAt()).isNotNull();
        PersonalGroupClosureService.Page remaining=closures.closures(worker,page.nextCursor(),1);
        assertThat(remaining.items()).hasSize(1);assertThat(remaining.nextCursor()).isNull();
        assertThat(remaining.items().getFirst().groupId()).isNotEqualTo(page.items().getFirst().groupId());
        org.springframework.security.core.Authentication unrelated=worker("other-service",now.plusSeconds(600));
        assertThatThrownBy(()->closures.closures(unrelated,null,1)).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(403));
        org.springframework.security.core.Authentication expired=worker("document-service",now.minusSeconds(1));
        assertThatThrownBy(()->closures.closures(expired,null,1)).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(403));
    }
    @Test void ownerMustCloseGroupsBeforeAccountRemovalAndAwaitDeadlineBeforeUnlink(){
        PersonalGroupService.GroupView group=service.create(as(owner),owner,"Owned",UUID.randomUUID());
        TransactionTemplate transactions=new TransactionTemplate(transactionManager);
        assertThatThrownBy(()->transactions.executeWithoutResult(tx->departure.assertDepartureAllowed(owner,Instant.now(),true)))
            .isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(409));
        PersonalGroupService.GroupView preparing=service.scheduleDeletion(as(owner),owner,group.id());
        assertThatThrownBy(()->transactions.executeWithoutResult(tx->departure.assertDepartureAllowed(owner,Instant.now(),true)))
            .isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(409));
        closures.confirmNotices(worker("document-service",now.plusSeconds(600)),group.id(),preparing.version(),UUID.randomUUID());
        transactions.executeWithoutResult(tx->departure.assertDepartureAllowed(owner,Instant.now(),true));
        assertThatThrownBy(()->transactions.executeWithoutResult(tx->departure.assertDepartureAllowed(owner,Instant.now(),false)))
            .isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(409));
        jdbc.update("UPDATE iam_group SET purge_after=? WHERE id=?",Timestamp.from(now.minusSeconds(1)),bytes(group.id()));
        transactions.executeWithoutResult(tx->departure.assertDepartureAllowed(owner,Instant.now(),false));
    }
    @Test void nonownerDepartureRevokesMembershipInvitationsDeveloperFactorsWithoutChangingCatalog(){
        PersonalGroupService.GroupView group=service.create(as(owner),owner,"Membership",UUID.randomUUID());
        PersonalGroupService.Invitation invitation=service.invite(as(owner),owner,group.id(),member,UUID.randomUUID());
        service.respond(as(member),member,invitation.id(),true);
        PersonalGroupService.GroupView pending=service.create(as(owner),owner,"Pending",UUID.randomUUID());
        PersonalGroupService.Invitation pendingInvitation=service.invite(as(owner),owner,pending.id(),member,UUID.randomUUID());
        jdbc.update("INSERT INTO iam_developer_eligibility(account_id,status,version,provisioned_by,reason,updated_at) VALUES(?,'ACTIVE',1,'integration','fixture',?)",bytes(member),Timestamp.from(now));
        jdbc.update("INSERT INTO iam_developer_factor(secret_hash,account_id,expires_at) VALUES(?,?,?)","a".repeat(64),bytes(member),Timestamp.from(now.plusSeconds(3600)));
        long revision=jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL'",Long.class);
        TransactionTemplate transactions=new TransactionTemplate(transactionManager);
        transactions.executeWithoutResult(tx->departure.depart(member,Instant.now(),null,users.get(member),null));
        assertThat(jdbc.queryForObject("SELECT status FROM personal_group_member WHERE group_id=? AND account_id=?",String.class,bytes(group.id()),bytes(member))).isEqualTo("REVOKED");
        assertThat(jdbc.queryForObject("SELECT status FROM personal_group_invitation WHERE id=?",String.class,bytes(pendingInvitation.id()))).isEqualTo("REVOKED");
        assertThat(jdbc.queryForObject("SELECT status FROM iam_developer_eligibility WHERE account_id=?",String.class,bytes(member))).isEqualTo("REVOKED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM iam_developer_factor WHERE account_id=?",Integer.class,bytes(member))).isZero();
        assertThat(jdbc.queryForObject("SELECT revision FROM iam_policy_revision WHERE id='GLOBAL'",Long.class)).isEqualTo(revision);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type='PERSONAL_GROUP_ACCOUNT_DEPARTED' AND aggregate_id IN (?,?)",Integer.class,bytes(group.id()),bytes(pending.id()))).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM personal_group_audit WHERE event_type='PERSONAL_GROUP_ACCOUNT_DEPARTED' AND session_id IS NULL",Integer.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type='PERSONAL_GROUP_ACCOUNT_DEPARTED' AND JSON_TYPE(JSON_EXTRACT(payload,'$.actorAccountId'))='NULL'",Integer.class)).isEqualTo(2);
        assertThatThrownBy(()->service.get(as(member),member,group.id())).isInstanceOf(ResponseStatusException.class);
        transactions.executeWithoutResult(tx->departure.depart(member,Instant.now(),member,users.get(member),null));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type='PERSONAL_GROUP_ACCOUNT_DEPARTED' AND aggregate_id IN (?,?)",Integer.class,bytes(group.id()),bytes(pending.id()))).isEqualTo(2);
    }
    @Test void noticeAcknowledgementIsVersionedRetrySafeAndDoesNotExtendDeadline(){
        PersonalGroupService.GroupView group=service.create(as(owner),owner,"Notice receipt",UUID.randomUUID());
        PersonalGroupService.Invitation invitation=service.invite(as(owner),owner,group.id(),member,UUID.randomUUID());
        service.respond(as(member),member,invitation.id(),true);
        service.remove(as(owner),owner,group.id(),member,false);
        PersonalGroupService.GroupView preparing=service.scheduleDeletion(as(owner),owner,group.id());
        org.springframework.security.core.Authentication worker=worker("document-service",now.plusSeconds(600));
        UUID receipt=UUID.randomUUID();
        assertThatThrownBy(()->closures.confirmNotices(worker,group.id(),preparing.version()-1,receipt)).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(409));
        PersonalGroupClosureService.Closure closing=closures.confirmNotices(worker,group.id(),preparing.version(),receipt);
        PersonalGroupClosureService.Closure retry=closures.confirmNotices(worker,group.id(),preparing.version(),receipt);
        assertThat(retry.groupVersion()).isEqualTo(closing.groupVersion());assertThat(retry.purgeAfter()).isEqualTo(closing.purgeAfter());
        assertThat(closing.purgeEligible()).isFalse();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM account_security_notice WHERE code='PERSONAL_GROUP_DELETION_SCHEDULED' AND account_id=?",Integer.class,bytes(member))).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM outbox_event WHERE event_type='PERSONAL_GROUP_DELETION_SCHEDULED' AND aggregate_id=?",Integer.class,bytes(group.id()))).isEqualTo(1);
        assertThatThrownBy(()->closures.confirmNotices(worker,group.id(),closing.groupVersion(),UUID.randomUUID())).isInstanceOfSatisfying(ResponseStatusException.class,e->assertThat(e.getStatusCode().value()).isEqualTo(409));
        jdbc.update("UPDATE iam_group SET purge_after=? WHERE id=?",Timestamp.from(now.minusSeconds(1)),bytes(group.id()));
        PersonalGroupClosureService.Closure due=closures.state(worker,group.id());assertThat(due.purgeEligible()).isTrue();assertThat(due.checkedAt()).isNotNull();
    }
    private UUID actor(String name,String type){UUID user=UUID.randomUUID(),account=UUID.randomUUID();Timestamp timestamp=Timestamp.from(now);users.put(account,user);jdbc.update("INSERT INTO users(id,display_name,status,created_at,updated_at) VALUES(?,?,'ACTIVE',?,?)",bytes(user),name,timestamp,timestamp);jdbc.update("INSERT INTO user_account(id,user_id,type,display_name,status,created_at,updated_at) VALUES(?,?,?,?,'ACTIVE',?,?)",bytes(account),bytes(user),type,name,timestamp,timestamp);return account;}
    private Jwt as(UUID account){Jwt jwt=Jwt.withTokenValue("token").header("alg","RS256").subject(account.toString()).claim("sid",UUID.randomUUID().toString()).expiresAt(now.plusSeconds(600)).build();SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt,List.of()));return jwt;}
    private org.springframework.security.core.Authentication worker(String identity,Instant expires){Jwt jwt=Jwt.withTokenValue("worker-token").header("alg","RS256").subject(identity).claim("azp",identity).expiresAt(expires).build();org.springframework.security.core.Authentication authentication=new JwtAuthenticationToken(jwt,List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_iam.authorization.read")));SecurityContextHolder.getContext().setAuthentication(authentication);return authentication;}
}
