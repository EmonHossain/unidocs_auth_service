package com.unidocs.auth.user.domain;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Objects;
import java.util.UUID;
import jakarta.persistence.*;

@Entity
@Table(name = "user_profile")
public class UserProfile {
    @Id private UUID userId;
    @Column(length = 100) private String firstName;
    @Column(length = 100) private String middleName;
    @Column(length = 100) private String lastName;
    private LocalDate dateOfBirth;
    @Column(length = 512) private String profileImageKey;
    @Column(length = 35) private String locale;
    @Column(length = 64) private String timeZone;
    @Column(nullable = false) private Instant updatedAt;

    protected UserProfile() { }

    public UserProfile(UUID userId, Instant now) {
        this.userId = Objects.requireNonNull(userId);
        this.updatedAt = Objects.requireNonNull(now);
    }
}
