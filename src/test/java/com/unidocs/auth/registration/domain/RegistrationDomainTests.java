package com.unidocs.auth.registration.domain;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.unidocs.auth.account.domain.AccountGroup;
import com.unidocs.auth.account.domain.UserAccount;
import com.unidocs.auth.registration.application.VerificationTokens;
import com.unidocs.auth.registration.domain.PendingRegistration;
import com.unidocs.auth.registration.domain.ProvisionedIdentity;
import com.unidocs.auth.registration.domain.RegistrationVerification;

import static org.assertj.core.api.Assertions.*;

class RegistrationDomainTests {
    private final Instant now = Instant.parse("2026-10-02T12:00:00Z");

    private RegistrationVerification verification() {
        return new RegistrationVerification(UUID.randomUUID(), UUID.randomUUID(), "user@example.com",
                new VerificationTokens().hash("token"), now, now.plusSeconds(900));
    }

    @Test
    void fifthFailurePermanentlyBlocksEvenCorrectToken() {
        RegistrationVerification verification = verification();
        for (int i = 0; i < 5; i++) { assertThat(verification.attempt(false, now)).isFalse(); }
        assertThat(verification.status()).isEqualTo(VerificationStatus.FAILED);
        assertThat(verification.attempt(true, now)).isFalse();
        assertThat(verification.attemptCount()).isEqualTo(5);
    }

    @Test
    void expirationBoundaryAndSuccessfulTokenReplayAreRejected() {
        RegistrationVerification expired = verification();
        assertThat(expired.attempt(true, now.plusSeconds(900))).isFalse();
        assertThat(expired.status()).isEqualTo(VerificationStatus.EXPIRED);
        RegistrationVerification verified = verification();
        assertThat(verified.attempt(true, now)).isTrue();
        assertThat(verified.attempt(true, now)).isFalse();
    }

    @Test
    void registrationRemainsVerifiedRatherThanCompleted() {
        PendingRegistration registration = new PendingRegistration(UUID.randomUUID(), "User", "user@example.com", "hash",
                now, now.plusSeconds(86400));
        registration.verify(now);
        assertThat(registration.status()).isEqualTo(RegistrationStatus.VERIFIED);
        assertThat(registration.expireIfNecessary(now.plusSeconds(86400))).isFalse();
        assertThatThrownBy(() -> registration.verify(now)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void sixDigitCodesUseIndependentSaltedHashesAndRejectWrongValues() {
        VerificationTokens tokens = new VerificationTokens();
        String token = tokens.generate();
        assertThat(token).matches("[0-9]{6}");
        assertThat(tokens.hash(token)).hasSize(60).isNotEqualTo(token).isNotEqualTo(tokens.hash(token));
        assertThat(tokens.matches(token, tokens.hash(token))).isTrue();
        assertThat(tokens.matches("wrong", tokens.hash(token))).isFalse();
    }

    @Test
    void registrationExpiresAtExactBoundaryAndCannotBeVerified() {
        PendingRegistration registration = new PendingRegistration(UUID.randomUUID(), "User", "user@example.com", "hash",
                now, now.plusSeconds(86400));
        assertThat(registration.expireIfNecessary(now.plusSeconds(86399))).isFalse();
        assertThat(registration.expireIfNecessary(now.plusSeconds(86400))).isTrue();
        assertThat(registration.status()).isEqualTo(RegistrationStatus.EXPIRED);
        assertThatThrownBy(() -> registration.verify(now.plusSeconds(86400)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void provisioningRequiresVerificationAndCannotCompleteTwiceOrAfterDeadline() {
        PendingRegistration pending = new PendingRegistration(UUID.randomUUID(), "User", "user@example.com", "hash",
                now, now.plusSeconds(86400));
        assertThatThrownBy(() -> ProvisionedIdentity.fromVerified(pending, now)).isInstanceOf(IllegalStateException.class);
        pending.verify(now);
        ProvisionedIdentity identity = ProvisionedIdentity.fromVerified(pending, now);
        assertThat(identity.preference().preferredAccountId()).isEqualTo(identity.account().id());
        assertThat(identity.loginIdentity().passwordHash()).isEqualTo("hash");
        assertThat(identity.loginIdentity().credentialVersion()).isEqualTo(1);
        assertThatThrownBy(() -> pending.complete(identity, now.plusSeconds(86400)))
                .isInstanceOf(IllegalStateException.class);
        pending.complete(identity, now);
        assertThat(pending.status()).isEqualTo(RegistrationStatus.COMPLETED);
        assertThat(pending.provisionedUserId()).isEqualTo(identity.user().id());
        assertThatThrownBy(() -> pending.complete(identity, now)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void initialAccountLinkMustBelongToTheGroupOwner() {
        AccountGroup group = new com.unidocs.auth.account.domain.AccountGroup(UUID.randomUUID(), UUID.randomUUID(), now);
        UserAccount account = new com.unidocs.auth.account.domain.UserAccount(UUID.randomUUID(), UUID.randomUUID(), "Personal", now);
        assertThatThrownBy(() -> new com.unidocs.auth.account.domain.AccountGroupMember(group, account, now))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void completionRequestsDoNotExposeTokensThroughToString() {
        assertThat(new com.unidocs.auth.registration.api.RegistrationCompletionRequest("completion-secret").toString())
                .doesNotContain("completion-secret");
    }
}
