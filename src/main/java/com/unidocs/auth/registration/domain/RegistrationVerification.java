package com.unidocs.auth.registration.domain;

import java.time.Instant;
import java.util.UUID;
import jakarta.persistence.*;

@Entity
@Table(name = "registration_verification")
public class RegistrationVerification {
    public static final int MAX_ATTEMPTS = 5;
    @Id private UUID id;
    @Column(nullable = false) private UUID pendingRegistrationId;
    @Column(nullable = false, length = 32) private String verificationType;
    @Column(nullable = false, length = 254) private String destination;
    @Column(nullable = false, length = 64) private String tokenHash;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private VerificationStatus status;
    @Column(nullable = false) private int attemptCount;
    @Column(nullable = false) private Instant createdAt;
    @Column(nullable = false) private Instant expiresAt;
    private Instant verifiedAt;

    protected RegistrationVerification() { }

    public RegistrationVerification(UUID id, UUID registrationId, String destination, String tokenHash,
            Instant now, Instant expiresAt) {
        if (id == null || registrationId == null || destination == null || destination.isBlank()
                || destination.length() > 254 || tokenHash == null || !(tokenHash.matches("[0-9a-f]{64}") || (tokenHash.startsWith("$2") && tokenHash.length() == 60))
                || now == null || expiresAt == null || !expiresAt.isAfter(now)) {
            throw new IllegalArgumentException("Invalid verification.");
        }
        this.id = id;
        this.pendingRegistrationId = registrationId;
        this.verificationType = "EMAIL_TOKEN";
        this.destination = destination;
        this.tokenHash = tokenHash;
        this.status = VerificationStatus.PENDING;
        this.createdAt = now;
        this.expiresAt = expiresAt;
    }

    public boolean expireIfNecessary(Instant now) {
        if (status == VerificationStatus.PENDING && !now.isBefore(expiresAt)) {
            status = VerificationStatus.EXPIRED;
        }
        return status == VerificationStatus.EXPIRED;
    }

    public boolean attempt(boolean matches, Instant now) {
        if (expireIfNecessary(now) || status != VerificationStatus.PENDING) {
            return false;
        }
        attemptCount++;
        if (matches) {
            status = VerificationStatus.VERIFIED;
            verifiedAt = now;
            return true;
        }
        if (attemptCount >= MAX_ATTEMPTS) {
            status = VerificationStatus.FAILED;
        }
        return false;
    }

    public VerificationStatus status() { return status; }
    public int attemptCount() { return attemptCount; }
    public String tokenHash() { return tokenHash; }
}
