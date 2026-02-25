package com.unidocs.auth.organization.domain;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import jakarta.persistence.*;
@Entity
@Table(name="organization_auth_policy")
public class OrganizationAuthPolicy {
    public enum AuthMethod { PASSWORD }
    @Id private UUID id;
    @Column(nullable=false) private UUID organizationId;
    @Enumerated(EnumType.STRING) @Column(nullable=false,length=32) private AuthMethod authMethod;
    @Column(length=253) private String emailDomain;
    @Column(nullable=false) private boolean enabled;
    @Column(nullable=false) private boolean allowPinUnlock;
    @Column(nullable=false) private boolean requireMfa;
    @Column(nullable=false) private Instant createdAt;
    @Column(nullable=false) private Instant updatedAt;
    protected OrganizationAuthPolicy() { }
    public OrganizationAuthPolicy(UUID id, UUID organizationId, Instant now) {
        this.id=Objects.requireNonNull(id); this.organizationId=Objects.requireNonNull(organizationId);
        authMethod=AuthMethod.PASSWORD; enabled=true; allowPinUnlock=false; requireMfa=false;
        createdAt=updatedAt=Objects.requireNonNull(now);
    }
}
