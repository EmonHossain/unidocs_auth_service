package com.unidocs.auth.user.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import jakarta.persistence.*;

@Entity
@Table(name = "user_preference")
public class UserPreference {
    public enum Theme { SYSTEM, LIGHT, DARK }
    @Id private UUID userId;
    private UUID preferredAccountId;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private Theme theme;
    @Column(length = 35) private String locale;
    @Column(nullable = false, length = 64) private String timeZone;
    @Column(nullable = false) private boolean emailNotifications;
    @Column(nullable = false) private boolean pushNotifications;
    @Column(nullable = false) private boolean securityNotifications;
    @Column(nullable = false) private Instant updatedAt;

    protected UserPreference() { }

    public UserPreference(UUID userId, UUID personalAccountId, Instant now) {
        this.userId = Objects.requireNonNull(userId);
        this.preferredAccountId = Objects.requireNonNull(personalAccountId);
        this.theme = Theme.SYSTEM;
        this.timeZone = "UTC";
        this.securityNotifications = true;
        this.updatedAt = Objects.requireNonNull(now);
    }

    public UUID preferredAccountId() { return preferredAccountId; }
}
