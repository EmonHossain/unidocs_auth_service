package com.unidocs.auth.user.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import jakarta.persistence.*;

@Entity
@Table(name = "user_contact")
public class UserContact {
    public enum Type { EMAIL }
    @Id private UUID id;
    @Column(nullable = false) private UUID userId;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private Type type;
    @Column(nullable = false, length = 254) private String value;
    @Column(name = "is_primary", nullable = false) private boolean primary;
    @Column(nullable = false) private boolean verified;
    @Column(nullable = false) private Instant verifiedAt;
    @Column(nullable = false) private Instant createdAt;

    protected UserContact() { }

    public UserContact(UUID id, UUID userId, String verifiedEmail, Instant verifiedAt, Instant now) {
        this.id = Objects.requireNonNull(id);
        this.userId = Objects.requireNonNull(userId);
        if (verifiedEmail == null || verifiedEmail.isBlank() || verifiedEmail.length() > 254) {
            throw new IllegalArgumentException("Invalid verified contact.");
        }
        this.type = Type.EMAIL;
        this.value = verifiedEmail;
        this.primary = this.verified = true;
        this.verifiedAt = Objects.requireNonNull(verifiedAt);
        this.createdAt = Objects.requireNonNull(now);
        if (verifiedAt.isAfter(now)) { throw new IllegalArgumentException("Invalid contact verification time."); }
    }
}
