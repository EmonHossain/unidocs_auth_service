package com.unidocs.auth.account;

import com.unidocs.auth.session.domain.SessionGrantPolicy;
import com.unidocs.auth.session.domain.UserSession;
import java.time.*;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import com.unidocs.auth.account.domain.AccountChallenge;
import com.unidocs.auth.account.domain.AccountChallenge.*;
import com.unidocs.auth.credential.domain.AccountCredential;
import com.unidocs.auth.session.domain.*;
import static org.assertj.core.api.Assertions.*;
class AccountChallengeTests {
    private final Instant now = Instant.parse("2026-10-02T10:00:00Z");
    @Test void challengeBoundariesAreStrict() {
        AccountChallenge challenge = new AccountChallenge(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),Purpose.UNLOCK,Method.PIN,
                "ACCOUNT_CREDENTIAL",UUID.randomUUID(),1,1,"PENDING",0,now.plusSeconds(120));
        assertThat(challenge.pendingAt(now)).isTrue(); assertThat(challenge.pendingAt(now.plusSeconds(120))).isFalse();
    }
    @Test void credentialLockoutExpiresAtBoundaryAndSecretIsRedacted() {
        AccountCredential credential = new AccountCredential(UUID.randomUUID(),UUID.randomUUID(),"secret-hash","ACTIVE",1,5,now.plusSeconds(900));
        assertThat(credential.usableAt(now)).isFalse(); assertThat(credential.usableAt(now.plusSeconds(900))).isTrue();
        assertThat(credential.toString()).doesNotContain("secret-hash");
    }
    @Test void policyNeverExtendsSessionDeadlineAndRejectsInvalidLimits() {
        SessionGrantPolicy policy = new SessionGrantPolicy(Duration.ofMinutes(30),Duration.ofHours(12),1);
        UserSession session = new UserSession(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),"ACTIVE",now,now,now.plusSeconds(60),null);
        assertThat(policy.absoluteExpiry(now,session)).isEqualTo(session.expiresAt());
        assertThat(policy.idleExpiry(now,session.expiresAt())).isEqualTo(session.expiresAt());
        assertThatThrownBy(() -> new SessionGrantPolicy(Duration.ZERO,Duration.ofHours(12),1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SessionGrantPolicy(Duration.ofHours(2),Duration.ofHours(1),1)).isInstanceOf(IllegalArgumentException.class);
    }
}
