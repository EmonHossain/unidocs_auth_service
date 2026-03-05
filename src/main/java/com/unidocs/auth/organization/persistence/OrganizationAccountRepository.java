package com.unidocs.auth.organization.persistence;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.*;

import jakarta.persistence.EntityManager;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import com.unidocs.auth.account.domain.*;
import com.unidocs.auth.account.domain.AccountGroupMember;
import com.unidocs.auth.account.domain.UserAccount.Type;
import com.unidocs.auth.account.domain.UserAccount;
import com.unidocs.auth.authentication.domain.LoginIdentity;
import com.unidocs.auth.organization.api.OrganizationAccountResponse;
import com.unidocs.auth.organization.domain.*;
import com.unidocs.auth.organization.domain.OrganizationMembership;
import com.unidocs.auth.session.application.SessionAccess.Context;

import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Repository
public class OrganizationAccountRepository {
    private final JdbcTemplate jdbc;
    private final EntityManager entities;
    public OrganizationAccountRepository(JdbcTemplate jdbc,EntityManager entities) { this.jdbc=jdbc; this.entities=entities; }
    public record Provisioned(OrganizationAccountResponse response,UUID userId,UUID groupId,UUID identityId,
            String passwordHash,long credentialVersion,boolean available) {
        @Override public String toString() { return "Provisioned[REDACTED]"; }
    }
    public Optional<Provisioned> provisioned(UUID invitation) {
        return jdbc.query("""
            SELECT a.*,i.id identity_id,i.password_hash,i.credential_version,m.id membership_id,g.account_group_id,
                (a.status='ACTIVE' AND i.status='ACTIVE' AND m.status='ACTIVE' AND g.status='LINKED') available
            FROM organization_invitation v JOIN user_account a ON a.id=v.accepted_account_id
            JOIN login_identity i ON i.account_id=a.id AND i.type='ACCOUNT_ID'
            JOIN organization_membership m ON m.id=v.membership_id
            JOIN account_group_member g ON g.account_id=a.id
            WHERE v.id=? AND v.status='ACCEPTED' AND v.provisioning_account_id IS NOT NULL
            """,(rs,n)->new Provisioned(new OrganizationAccountResponse(uuid(rs.getBytes("id")),uuid(rs.getBytes("organization_id")),
                    uuid(rs.getBytes("membership_id")),UserAccount.Type.valueOf(rs.getString("type")),rs.getString("display_name")),
                    uuid(rs.getBytes("user_id")),uuid(rs.getBytes("account_group_id")),uuid(rs.getBytes("identity_id")),
                    rs.getString("password_hash"),rs.getLong("credential_version"),rs.getBoolean("available")),bytes(invitation)).stream().findFirst();
    }
    public boolean hasHumanMembership(UUID organization,UUID user) {
        // Includes REVOKED and legacy Personal memberships: provisioning cannot bypass either.
        return !jdbc.query("""
            SELECT m.id FROM organization_membership m JOIN user_account a ON a.id=m.account_id
            WHERE m.organization_id=? AND a.user_id=? AND m.status<>'PURGED' AND a.status<>'PURGED' LIMIT 1
            """,(rs,n)->rs.getBytes(1),bytes(organization),bytes(user)).isEmpty();
    }
    public Organization.Type type(UUID organization) {
        return Organization.Type.valueOf(jdbc.queryForObject("SELECT type FROM organization WHERE id=?",String.class,bytes(organization)));
    }
    public OrganizationAccountResponse create(Context actor,UUID actorAccount,UUID organization,String name,String hash,String verifiedEmail) {
        Type type=UserAccount.Type.valueOf(type(organization).name());
        UserAccount account=new UserAccount(UUID.randomUUID(),actor.owner().userId(),organization,type,name,actor.now());
        LoginIdentity identity=new LoginIdentity(UUID.randomUUID(),account.id(),LoginIdentity.Type.ACCOUNT_ID,account.id().toString(),hash,actor.now());
        AccountGroupMember link=new AccountGroupMember(account,actor.session().accountGroupId(),actor.owner().userId(),actorAccount,actor.now());
        OrganizationMembership membership=new OrganizationMembership(UUID.randomUUID(),organization,account.id(),verifiedEmail,OrganizationMembership.Role.MEMBER,actor.now());
        entities.persist(account); entities.flush();
        entities.persist(identity); entities.flush();
        entities.persist(link); entities.flush();
        entities.persist(membership); entities.flush();
        jdbc.update("UPDATE organization SET authorization_version=authorization_version+1,updated_at=? WHERE id=?",
                java.sql.Timestamp.from(actor.now()),bytes(organization));
        return new OrganizationAccountResponse(account.id(),organization,membership.id(),type,name);
    }
    public long authorizationVersion(UUID organization) {
        return jdbc.queryForObject("SELECT authorization_version FROM organization WHERE id=?",Long.class,bytes(organization));
    }
    private static UUID uuid(byte[] bytes) { ByteBuffer b=ByteBuffer.wrap(bytes); return new UUID(b.getLong(),b.getLong()); }
}
