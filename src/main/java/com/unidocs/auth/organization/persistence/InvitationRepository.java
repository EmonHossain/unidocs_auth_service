package com.unidocs.auth.organization.persistence;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import jakarta.persistence.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import com.unidocs.auth.organization.domain.*;
import static com.unidocs.auth.session.persistence.SessionRepository.bytes;

@Repository
public class InvitationRepository {
    private final EntityManager entities;
    private final JdbcTemplate jdbc;
    public InvitationRepository(EntityManager entities, JdbcTemplate jdbc) { this.entities=entities; this.jdbc=jdbc; }
    public boolean lockUsableOrganization(UUID organization) {
        return jdbc.query("""
            SELECT o.status='ACTIVE' AND p.enabled=true AND p.auth_method='PASSWORD'
                AND p.require_mfa=false AND p.email_domain IS NULL AS usable
            FROM organization o JOIN organization_auth_policy p ON p.organization_id=o.id WHERE o.id=? FOR UPDATE
            """,(rs,n)->rs.getBoolean("usable"),bytes(organization)).stream().findFirst().orElse(false);
    }
    public List<OrganizationInvitation> pending(UUID organization, String email) {
        return entities.createQuery("SELECT i FROM OrganizationInvitation i WHERE i.organizationId=:organization AND i.officialEmail=:email AND i.status=:status",OrganizationInvitation.class)
                .setParameter("organization",organization).setParameter("email",email).setParameter("status",OrganizationInvitation.Status.PENDING)
                .setLockMode(LockModeType.PESSIMISTIC_WRITE).getResultList();
    }
    public Optional<OrganizationInvitation> lock(UUID invitation) {
        return Optional.ofNullable(entities.find(OrganizationInvitation.class,invitation,LockModeType.PESSIMISTIC_WRITE));
    }
    public void save(OrganizationInvitation invitation) { entities.persist(invitation); entities.flush(); }
    public void flush() { entities.flush(); }
    public boolean issuerCurrent(OrganizationInvitation invitation) {
        // Read availability without locking another human's group (which may be waiting for this organization).
        boolean available=jdbc.query("""
            SELECT 1 FROM user_account a JOIN users u ON u.id=a.user_id
            JOIN account_group_member m ON m.account_id=a.id JOIN account_group g ON g.id=m.account_group_id
            WHERE a.id=? AND a.status='ACTIVE' AND u.status='ACTIVE' AND m.status='LINKED'
                AND g.status='ACTIVE' AND g.user_id=a.user_id
                AND %s
            """.formatted(OrganizationAccountScope.PASSWORD),(rs,n)->true,bytes(invitation.createdByAccountId())).stream().findFirst().orElse(false);
        // The organization lock serializes membership mutations.
        return available && jdbc.query("""
            SELECT 1 FROM organization_membership WHERE id=? AND organization_id=? AND account_id=?
                AND version=? AND status='ACTIVE' AND role IN ('OWNER','ADMIN') FOR SHARE
            """,(rs,n)->true,bytes(invitation.issuerMembershipId()),bytes(invitation.organizationId()),
                bytes(invitation.createdByAccountId()),invitation.issuerMembershipVersion()).stream().findFirst().orElse(false);
    }
    public boolean accountEmail(UUID account, String email) {
        return jdbc.query("SELECT 1 FROM login_identity WHERE account_id=? AND type='EMAIL' AND status='ACTIVE' AND identifier=? FOR SHARE",
                (rs,n)->true,bytes(account),email).stream().findFirst().orElse(false);
    }
    public boolean userCanJoin(UUID organization, UUID user) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM organization_account_restriction WHERE organization_id=? AND user_id=? AND status IN('REMOVED','BLACKLISTED')", Integer.class,bytes(organization),bytes(user)) == 0;
    }
    public boolean hasMembership(UUID organization, UUID account) {
        return !jdbc.query("SELECT 1 FROM organization_membership WHERE organization_id=? AND account_id=? AND status<>'PURGED' FOR UPDATE",
                (rs,n)->true,bytes(organization),bytes(account)).isEmpty();
    }
    public void activate(OrganizationMembership membership, UUID organization, Instant now) {
        entities.persist(membership); entities.flush();
        jdbc.update("UPDATE organization SET authorization_version=authorization_version+1,updated_at=? WHERE id=?",Timestamp.from(now),bytes(organization));
    }
}
