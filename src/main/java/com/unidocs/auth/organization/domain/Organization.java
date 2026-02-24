package com.unidocs.auth.organization.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import jakarta.persistence.*;

@Entity
@Table(name = "organization")
public class Organization {
    public enum Type { COMPANY, UNIVERSITY, CUSTOM }
    public enum Status { ACTIVE, DISABLED }
    @Id private UUID id;
    @Column(nullable=false,length=100) private String name;
    @Column(nullable=false,length=63) private String slug;
    @Enumerated(EnumType.STRING) @Column(nullable=false,length=32) private Type type;
    @Enumerated(EnumType.STRING) @Column(nullable=false,length=32) private Status status;
    @Column(nullable=false) private long authorizationVersion;
    @Column(nullable=false) private UUID createdByAccountId;
    @Column(nullable=false) private UUID creationRequestId;
    @Column(nullable=false,length=64) private String creationFingerprint;
    @Column(nullable=false) private Instant createdAt;
    @Column(nullable=false) private Instant updatedAt;
    protected Organization() { }
    public Organization(UUID id, String name, String slug, Type type, UUID creator, UUID request, String fingerprint, Instant now) {
        if (name == null || name.isBlank() || name.strip().length() > 100 || slug == null || slug.length()<3 || slug.length()>63
                || !slug.matches("[a-z0-9]+(?:-[a-z0-9]+)*") || fingerprint == null || !fingerprint.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Invalid organization.");
        }
        this.id=Objects.requireNonNull(id); this.name=name.strip(); this.slug=slug; this.type=Objects.requireNonNull(type);
        createdByAccountId=Objects.requireNonNull(creator); creationRequestId=Objects.requireNonNull(request);
        creationFingerprint=fingerprint; status=Status.ACTIVE; authorizationVersion=1;
        createdAt=updatedAt=Objects.requireNonNull(now);
    }
    public UUID id() { return id; }
    public String name() { return name; }
    public String slug() { return slug; }
    public Type type() { return type; }
}
