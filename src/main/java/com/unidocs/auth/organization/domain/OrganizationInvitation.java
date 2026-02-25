package com.unidocs.auth.organization.domain;

import java.time.*;
import java.util.*;
import jakarta.persistence.*;

@Entity
@Table(name="organization_invitation")
public class OrganizationInvitation {
    public enum Status { PENDING, ACCEPTED, EXPIRED, FAILED, SUPERSEDED }
    public static final Duration LIFETIME = Duration.ofHours(24);
    public static final int MAX_ATTEMPTS = 5;
    @Id private UUID id;
    @Column(nullable=false) private UUID organizationId;
    @Column(nullable=false) private UUID createdByAccountId;
    @Column(nullable=false) private UUID issuerMembershipId;
    @Column(nullable=false) private long issuerMembershipVersion;
    @Column(nullable=false,length=254) private String officialEmail;
    @Column(nullable=false,length=64) private String tokenHash;
    @Enumerated(EnumType.STRING) @Column(nullable=false,length=32) private Status status;
    @Column(nullable=false) private int attemptCount;
    @Column(nullable=false) private long version;
    @Column(nullable=false) private Instant createdAt;
    @Column(nullable=false) private Instant updatedAt;
    @Column(nullable=false) private Instant expiresAt;
    private Instant acceptedAt;
    private UUID acceptedAccountId;
    private UUID membershipId;
    private UUID provisioningAccountId;
    protected OrganizationInvitation() { }
    public OrganizationInvitation(UUID id, UUID organization, UUID issuerAccount, UUID issuerMembership,
            long issuerVersion, String email, String tokenHash, Instant now) {
        if (issuerVersion<1 || email==null || email.isBlank() || email.length()>254
                || tokenHash==null || !tokenHash.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Invalid invitation.");
        this.id=Objects.requireNonNull(id); organizationId=Objects.requireNonNull(organization);
        createdByAccountId=Objects.requireNonNull(issuerAccount); issuerMembershipId=Objects.requireNonNull(issuerMembership);
        issuerMembershipVersion=issuerVersion; officialEmail=email; this.tokenHash=tokenHash;
        createdAt=updatedAt=Objects.requireNonNull(now); expiresAt=now.plus(LIFETIME);
        status=Status.PENDING; version=1;
    }
    public boolean verifyProof(boolean matches, Instant now) {
        if(status!=Status.PENDING) return false;
        if(!now.isBefore(expiresAt)) { status=Status.EXPIRED; changed(now); return false; }
        if(matches) return true;
        attemptCount++;
        if(attemptCount>=MAX_ATTEMPTS) status=Status.FAILED;
        changed(now); return false;
    }
    public void accept(UUID account, UUID membership, Instant now) {
        if(status!=Status.PENDING || !now.isBefore(expiresAt)) throw new IllegalStateException("Invitation is unavailable.");
        acceptedAccountId=Objects.requireNonNull(account); membershipId=Objects.requireNonNull(membership);
        acceptedAt=now; attemptCount++; status=Status.ACCEPTED; changed(now);
    }
    public void supersede(Instant now) {
        if(status!=Status.PENDING) throw new IllegalStateException("Invitation is unavailable.");
        status=now.isBefore(expiresAt)?Status.SUPERSEDED:Status.EXPIRED; changed(now);
    }
    public void acceptProvisioned(UUID actor, UUID account, UUID membership, Instant now) {
        Objects.requireNonNull(actor);
        accept(account,membership,now);
        provisioningAccountId=actor;
    }
    private void changed(Instant now) { version++; updatedAt=Objects.requireNonNull(now); }
    public UUID id() { return id; }
    public UUID organizationId() { return organizationId; }
    public UUID createdByAccountId() { return createdByAccountId; }
    public UUID issuerMembershipId() { return issuerMembershipId; }
    public long issuerMembershipVersion() { return issuerMembershipVersion; }
    public String officialEmail() { return officialEmail; }
    public String tokenHash() { return tokenHash; }
    public Status status() { return status; }
    public long version() { return version; }
    public int attemptCount() { return attemptCount; }
    public Instant expiresAt() { return expiresAt; }
    public UUID acceptedAccountId() { return acceptedAccountId; }
    public UUID membershipId() { return membershipId; }
    public UUID provisioningAccountId() { return provisioningAccountId; }
    @Override public String toString() { return "OrganizationInvitation[id="+id+",status="+status+"]"; }
}
