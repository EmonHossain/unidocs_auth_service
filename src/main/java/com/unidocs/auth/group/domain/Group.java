package com.unidocs.auth.group.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "iam_group")
public class Group {
    public enum Type { DEPARTMENT, COURSE, CLASS, TEAM, PROJECT, CUSTOM }
    public enum Status { ACTIVE, DISABLED }
    @Id private UUID id;
    @Column(nullable = false) private UUID organizationId;
    private UUID parentGroupId;
    @Column(nullable = false, length = 100) private String name;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private Type type;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private Status status;
    @Column(nullable = false) private long version;
    @Column(nullable = false) private UUID createdByAccountId;
    @Column(nullable = false) private UUID creationRequestId;
    @Column(nullable = false, length = 64) private String creationFingerprint;
    @Column(nullable = false) private Instant createdAt;
    @Column(nullable = false) private Instant updatedAt;

    protected Group() { }

    public Group(UUID id, UUID organization, UUID parent, String name, Type type,
            UUID creator, UUID request, String fingerprint, Instant now) {
        this.id = Objects.requireNonNull(id);
        organizationId = Objects.requireNonNull(organization);
        if (id.equals(parent) || fingerprint == null || !fingerprint.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Invalid group.");
        }
        parentGroupId = parent;
        this.name = normalizedName(name);
        this.type = Objects.requireNonNull(type);
        createdByAccountId = Objects.requireNonNull(creator);
        creationRequestId = Objects.requireNonNull(request);
        creationFingerprint = fingerprint;
        status = Status.ACTIVE;
        version = 1;
        createdAt = updatedAt = Objects.requireNonNull(now);
    }

    public static String normalizedName(String name) {
        if (name == null || name.isBlank() || name.strip().length() > 100
                || name.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Invalid group name.");
        }
        return name.strip();
    }
    public UUID id() { return id; }
    public UUID organizationId() { return organizationId; }
    public UUID parentGroupId() { return parentGroupId; }
    public String name() { return name; }
}
