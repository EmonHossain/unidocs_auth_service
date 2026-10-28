package com.unidocs.auth.authentication.domain;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import jakarta.persistence.*;

@Entity
@Table(name = "login_identity")
public class LoginIdentity {
    public enum Type { EMAIL, ACCOUNT_ID }
    public enum Status { ACTIVE, DISABLED }
    @Id private UUID id;
    @Column(nullable = false) private UUID accountId;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private Type type;
    @Column(nullable = false, length = 254) private String identifier;
    @Column(nullable = false, length = 255) private String passwordHash;
    @Column(length = 255) private String externalSubject;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private Status status;
    @Column(nullable = false) private long credentialVersion;
    private Instant lastAuthenticatedAt;
    @Column(nullable = false) private Instant createdAt;
    @Column(nullable = false) private Instant updatedAt;

    protected LoginIdentity() { }

    public LoginIdentity(UUID id, UUID accountId, String normalizedEmail, String passwordHash, Instant now) {
        this(id,accountId,Type.EMAIL,normalizedEmail,passwordHash,now);
    }

    public LoginIdentity(UUID id, UUID accountId, Type type, String identifier, String passwordHash, Instant now) {
        this.id = Objects.requireNonNull(id);
        this.accountId = Objects.requireNonNull(accountId);
        if (identifier == null || identifier.isBlank() || identifier.length() > 254
                || !identifier.equals(identifier.strip().toLowerCase(Locale.ROOT))
                || (type == Type.ACCOUNT_ID && !accountId.toString().equals(identifier))
                || passwordHash == null || passwordHash.isBlank() || passwordHash.length() > 255) {
            throw new IllegalArgumentException("Invalid login identity.");
        }
        this.type = Objects.requireNonNull(type);
        this.identifier = identifier;
        this.passwordHash = passwordHash;
        this.status = Status.ACTIVE;
        this.credentialVersion = 1;
        this.createdAt = this.updatedAt = Objects.requireNonNull(now);
    }

    public UUID accountId() { return accountId; }
    public String identifier() { return identifier; }
    public String passwordHash() { return passwordHash; }
    public long credentialVersion() { return credentialVersion; }
}
