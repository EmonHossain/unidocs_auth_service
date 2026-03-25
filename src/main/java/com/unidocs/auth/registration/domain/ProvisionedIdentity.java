package com.unidocs.auth.registration.domain;

import java.time.Instant;
import java.util.UUID;

import com.unidocs.auth.account.domain.*;
import com.unidocs.auth.account.domain.AccountGroup;
import com.unidocs.auth.account.domain.UserAccount;
import com.unidocs.auth.audit.domain.SecurityAuditEvent;
import com.unidocs.auth.authentication.domain.LoginIdentity;
import com.unidocs.auth.user.domain.*;
import com.unidocs.auth.user.domain.User;

public record ProvisionedIdentity(User user, UserProfile profile, UserContact contact,
        UserPreference preference, UserAccount account, LoginIdentity loginIdentity,
        AccountGroup accountGroup, AccountGroupMember groupMember,
        SecurityAuditEvent completionAudit, SecurityAuditEvent linkingAudit) {

    public static ProvisionedIdentity fromVerified(PendingRegistration registration, Instant now) {
        if (registration == null || registration.status() != RegistrationStatus.VERIFIED
                || now == null || now.isBefore(registration.verifiedAt())
                || !now.isBefore(registration.expiresAt())) {
            throw new IllegalStateException("Provisioning requires a current verified registration.");
        }
        User user = new User(UUID.randomUUID(), registration.displayName(), now);
        UserAccount account = new UserAccount(UUID.randomUUID(), user.id(), registration.displayName(), now);
        AccountGroup group = new AccountGroup(UUID.randomUUID(), user.id(), now);
        return new ProvisionedIdentity(user, new UserProfile(user.id(), now),
                new UserContact(UUID.randomUUID(), user.id(), registration.identifier(), registration.verifiedAt(), now),
                new UserPreference(user.id(), account.id(), now), account,
                new LoginIdentity(UUID.randomUUID(), account.id(), registration.identifier(), registration.passwordHash(), now),
                group, new AccountGroupMember(group, account, now),
                new SecurityAuditEvent(UUID.randomUUID(), user.id(), account.id(), SecurityAuditEvent.Type.REGISTRATION_COMPLETED, now),
                new SecurityAuditEvent(UUID.randomUUID(), user.id(), account.id(), SecurityAuditEvent.Type.ACCOUNT_LINKED, now));
    }
}
