package com.unidocs.auth.session;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.unidocs.auth.session.domain.*;
import com.unidocs.auth.session.domain.RefreshSecret;
import com.unidocs.auth.session.domain.SessionAccountGrant;
import com.unidocs.auth.session.domain.UserSession;

import static org.assertj.core.api.Assertions.*;

class SessionDomainTests {
    private static final Instant NOW = Instant.parse("2026-10-02T10:00:00Z");

    @Test void grantsExpireAtExactBoundariesAndCredentialVersionsMustMatch() {
        SessionAccountGrant grant = new SessionAccountGrant(UUID.randomUUID(), UUID.randomUUID(), "ACTIVE", "LOGIN", 3,
                NOW.plusSeconds(60), NOW.plusSeconds(120));
        assertThat(grant.activeAt(NOW, 3)).isTrue();
        assertThat(grant.activeAt(NOW, 4)).isFalse();
        assertThat(grant.activeAt(NOW.plusSeconds(60), 3)).isFalse();
        assertThat(grant.nextIdleExpiry(NOW)).isEqualTo(NOW.plusSeconds(120));
        SessionAccountGrant absolute = new SessionAccountGrant(grant.sessionId(), grant.accountId(), "ACTIVE", "LOGIN", 3,
                NOW.plusSeconds(120), NOW.plusSeconds(120));
        assertThat(absolute.activeAt(NOW.plusSeconds(120), 3)).isFalse();
    }

    @Test void sessionsHaveStrictDurableExpiryAndRevocation() {
        UserSession session = new UserSession(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), "ACTIVE", NOW, NOW,
                NOW.plusSeconds(60), null);
        assertThat(session.activeAt(NOW)).isTrue();
        assertThat(session.activeAt(NOW.plusSeconds(60))).isFalse();
        assertThat(new UserSession(session.id(), session.accountGroupId(), session.loginAccountId(), "REVOKED",
                NOW, NOW, session.expiresAt(), NOW).activeAt(NOW)).isFalse();
    }

    @Test void refreshSecretsHaveRandomEntropyAreHashedAndRedacted() {
        RefreshSecret first = RefreshSecret.create(); RefreshSecret second = RefreshSecret.create();
        assertThat(first.value()).isNotEqualTo(second.value());
        assertThat(first.secret()).hasSize(43);
        assertThat(first.hash()).hasSize(64).isNotEqualTo(first.secret());
        assertThat(first.matches(first.hash())).isTrue();
        assertThat(first.matches(second.hash())).isFalse();
        assertThat(RefreshSecret.parse(first.value()).value()).isEqualTo(first.value());
        assertThat(first.toString()).doesNotContain(first.secret());
        assertThatThrownBy(() -> RefreshSecret.parse("invalid")).isInstanceOf(IllegalArgumentException.class);
    }
}
