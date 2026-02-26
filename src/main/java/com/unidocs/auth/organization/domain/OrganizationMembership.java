package com.unidocs.auth.organization.domain;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import jakarta.persistence.*;
@Entity
@Table(name="organization_membership")
public class OrganizationMembership {
    public enum Role { OWNER, ADMIN, MEMBER }
    public enum Status { ACTIVE, REVOKED, PURGED }
    @Id private UUID id;
    @Column(nullable=false) private UUID organizationId;
    @Column(nullable=false) private UUID accountId;
    @Enumerated(EnumType.STRING) @Column(nullable=false,length=32) private Role role;
    @Enumerated(EnumType.STRING) @Column(nullable=false,length=32) private Status status;
    @Column(length=254) private String officialEmail;
    @Column(length=100) private String memberCode;
    @Column(length=255) private String externalIdentity;
    @Column(nullable=false) private long version;
    @Column(nullable=false) private Instant joinedAt;
    private Instant revokedAt;
    private UUID revokedBy;
    @Column(nullable=false) private Instant createdAt;
    @Column(nullable=false) private Instant updatedAt;
    protected OrganizationMembership() { }
    public OrganizationMembership(UUID id, UUID organization, UUID account, String verifiedEmail, Instant now) {
        this(id,organization,account,verifiedEmail,Role.OWNER,now);
    }
    public OrganizationMembership(UUID id, UUID organization, UUID account, String verifiedEmail, Role role, Instant now) {
        if (verifiedEmail==null || verifiedEmail.isBlank() || verifiedEmail.length()>254) throw new IllegalArgumentException("Verified contact is required.");
        this.id=Objects.requireNonNull(id); organizationId=Objects.requireNonNull(organization); accountId=Objects.requireNonNull(account);
        officialEmail=verifiedEmail; this.role=Objects.requireNonNull(role); status=Status.ACTIVE; version=1;
        joinedAt=createdAt=updatedAt=Objects.requireNonNull(now);
    }
    public UUID id() { return id; }
}
