package com.unidocs.auth.account.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import jakarta.persistence.*;

@Entity
@Table(name = "account_group_member")
public class AccountGroupMember {
    public enum Status { LINKED, DISCONNECTED }
    public enum LinkMethod { REGISTRATION, PASSWORD, PIN, INVITATION }
    @Id private UUID accountId;
    @Column(nullable = false) private UUID accountGroupId;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private Status status;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 32) private LinkMethod linkMethod;
    @Column(nullable = false) private UUID linkedByAccountId;
    @Column(nullable = false) private Instant linkedAt;
    private Instant disconnectedAt;

    protected AccountGroupMember() { }

    public AccountGroupMember(UserAccount account, UUID groupId, UUID groupOwner, UUID actorAccount, Instant now) {
        Objects.requireNonNull(account);
        if(!account.userId().equals(Objects.requireNonNull(groupOwner))) throw new IllegalArgumentException("Account link must have the same owner.");
        accountId=account.id(); accountGroupId=Objects.requireNonNull(groupId);
        linkedByAccountId=Objects.requireNonNull(actorAccount); status=Status.LINKED; linkMethod=LinkMethod.INVITATION;
        linkedAt=Objects.requireNonNull(now);
    }

    public AccountGroupMember(AccountGroup group, UserAccount personalAccount, Instant now) {
        Objects.requireNonNull(group);
        Objects.requireNonNull(personalAccount);
        if (!group.userId().equals(personalAccount.userId())) {
            throw new IllegalArgumentException("Initial account link must have the same owner.");
        }
        this.accountId = this.linkedByAccountId = personalAccount.id();
        this.accountGroupId = group.id();
        this.status = Status.LINKED;
        this.linkMethod = LinkMethod.REGISTRATION;
        this.linkedAt = Objects.requireNonNull(now);
    }
}
