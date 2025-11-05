package com.unidocs.auth.account.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import jakarta.persistence.*;

@Entity
@Table(name = "account_group")
public class AccountGroup {
    public enum Status { ACTIVE, DISABLED }
    @Id private UUID id;
    @Column(nullable = false) private UUID userId;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private Status status;
    @Column(nullable = false) private Instant createdAt;
    @Column(nullable = false) private Instant updatedAt;

    protected AccountGroup() { }

    public AccountGroup(UUID id, UUID userId, Instant now) {
        this.id = Objects.requireNonNull(id);
        this.userId = Objects.requireNonNull(userId);
        this.status = Status.ACTIVE;
        this.createdAt = this.updatedAt = Objects.requireNonNull(now);
    }

    public UUID id() { return id; }
    public UUID userId() { return userId; }
}
