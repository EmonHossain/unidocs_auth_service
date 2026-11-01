package com.unidocs.auth.user.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import jakarta.persistence.*;

@Entity
@Table(name = "users")
public class User {
    public enum Status { ACTIVE, DISABLED }
    @Id private UUID id;
    @Column(nullable = false, length = 100) private String displayName;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private Status status;
    private Instant lastLoginAt;
    @Column(nullable = false) private Instant createdAt;
    @Column(nullable = false) private Instant updatedAt;

    protected User() { }

    public User(UUID id, String displayName, Instant now) {
        this.id = Objects.requireNonNull(id);
        if (displayName == null || displayName.isBlank() || displayName.length() > 100) {
            throw new IllegalArgumentException("Invalid user display name.");
        }
        this.displayName = displayName;
        this.status = Status.ACTIVE;
        this.createdAt = this.updatedAt = Objects.requireNonNull(now);
    }

    public UUID id() { return id; }
    public String displayName() { return displayName; }
    public Status status() { return status; }
}
