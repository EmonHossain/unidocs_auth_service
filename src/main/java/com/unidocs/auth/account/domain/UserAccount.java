package com.unidocs.auth.account.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import jakarta.persistence.*;

@Entity
@Table(name = "user_account")
public class UserAccount {
    public enum Type { PERSONAL, COMPANY, UNIVERSITY, CUSTOM }
    public enum Status { ACTIVE, DISABLED, SOFT_DELETED, BLACKLISTED, PURGED }
    @Id private UUID id;
    @Column(nullable = false) private UUID userId;
    private UUID organizationId;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private Type type;
    @Column(nullable = false, length = 100) private String displayName;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private Status status;
    @Column(nullable = false) private Instant createdAt;
    @Column(nullable = false) private Instant updatedAt;

    protected UserAccount() { }

    public UserAccount(UUID id, UUID userId, String displayName, Instant now) {
        this(id,userId,null,Type.PERSONAL,displayName,now);
    }

    public UserAccount(UUID id, UUID userId, UUID organizationId, Type type, String displayName, Instant now) {
        this.id = Objects.requireNonNull(id);
        this.userId = Objects.requireNonNull(userId);
        if (displayName == null || displayName.isBlank() || displayName.length() > 100) {
            throw new IllegalArgumentException("Invalid account display name.");
        }
        this.displayName = displayName;
        this.type = Objects.requireNonNull(type);
        if ((type == Type.PERSONAL) != (organizationId == null)) throw new IllegalArgumentException("Invalid account scope.");
        this.organizationId = organizationId;
        this.status = Status.ACTIVE;
        this.createdAt = this.updatedAt = Objects.requireNonNull(now);
    }

    public UUID id() { return id; }
    public UUID userId() { return userId; }
    public UUID organizationId() { return organizationId; }
    public Type type() { return type; }
    public Status status() { return status; }
}
