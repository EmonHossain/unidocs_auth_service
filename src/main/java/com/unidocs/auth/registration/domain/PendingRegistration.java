package com.unidocs.auth.registration.domain;

import java.time.Instant;
import java.util.UUID;
import jakarta.persistence.*;

@Entity
@Table(name = "pending_registration")
public class PendingRegistration {
    @Id private UUID id;
    @Column(nullable = false, length = 32) private String registrationType;
    @Column(nullable = false, length = 100) private String displayName;
    @Column(nullable = false, length = 254) private String identifier;
    @Column(nullable = false, length = 32) private String identityType;
    @Column(nullable = false, length = 255) private String passwordHash;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private RegistrationStatus status;
    @Column(nullable = false) private Instant createdAt;
    @Column(nullable = false) private Instant expiresAt;
    private Instant verifiedAt;
    private Instant completedAt;
    private UUID provisionedUserId;
    private UUID provisionedAccountId;
    private UUID provisionedAccountGroupId;

    protected PendingRegistration() { }

    public PendingRegistration(UUID id, String displayName, String identifier, String passwordHash,
            Instant now, Instant expiresAt) {
        if (id == null || displayName == null || displayName.isBlank() || displayName.length() > 100
                || identifier == null || identifier.isBlank() || identifier.length() > 254
                || passwordHash == null || passwordHash.isBlank() || now == null
                || expiresAt == null || !expiresAt.isAfter(now)) {
            throw new IllegalArgumentException("Invalid pending registration.");
        }
        this.id = id;
        this.registrationType = "PERSONAL";
        this.displayName = displayName;
        this.identifier = identifier;
        this.identityType = "EMAIL";
        this.passwordHash = passwordHash;
        this.status = RegistrationStatus.PENDING_VERIFICATION;
        this.createdAt = now;
        this.expiresAt = expiresAt;
    }

    public boolean expireIfNecessary(Instant now) {
        if (status == RegistrationStatus.PENDING_VERIFICATION && !now.isBefore(expiresAt)) {
            status = RegistrationStatus.EXPIRED;
            return true;
        }
        return status == RegistrationStatus.EXPIRED;
    }

    public void verify(Instant now) {
        if (status != RegistrationStatus.PENDING_VERIFICATION || !now.isBefore(expiresAt)) {
            throw new IllegalStateException("Registration cannot be verified.");
        }
        status = RegistrationStatus.VERIFIED;
        verifiedAt = now;
    }

    public UUID id() { return id; }
    public String displayName() { return displayName; }
    public String identifier() { return identifier; }
    public String passwordHash() { return passwordHash; }
    public Instant verifiedAt() { return verifiedAt; }
    public Instant completedAt() { return completedAt; }
    public UUID provisionedUserId() { return provisionedUserId; }
    public UUID provisionedAccountId() { return provisionedAccountId; }
    public UUID provisionedAccountGroupId() { return provisionedAccountGroupId; }
    public RegistrationStatus status() { return status; }
    public Instant expiresAt() { return expiresAt; }

    public void complete(ProvisionedIdentity identity, Instant now) {
        if (status != RegistrationStatus.VERIFIED || identity == null || now == null
                || now.isBefore(verifiedAt) || !now.isBefore(expiresAt)
                || !identity.user().displayName().equals(displayName)
                || !identity.loginIdentity().identifier().equals(identifier)
                || !identity.loginIdentity().passwordHash().equals(passwordHash)) {
            throw new IllegalStateException("Registration cannot be completed.");
        }
        provisionedUserId = identity.user().id();
        provisionedAccountId = identity.account().id();
        provisionedAccountGroupId = identity.accountGroup().id();
        completedAt = now;
        status = RegistrationStatus.COMPLETED;
    }
}
