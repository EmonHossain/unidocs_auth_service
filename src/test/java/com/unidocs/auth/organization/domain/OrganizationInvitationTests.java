package com.unidocs.auth.organization.domain;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.unidocs.auth.organization.domain.OrganizationInvitation;

import static org.assertj.core.api.Assertions.*;

class OrganizationInvitationTests {
    private final Instant now=Instant.parse("2026-10-02T12:00:00Z");
    private OrganizationInvitation invitation() {
        return new OrganizationInvitation(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),1,"verified@example.com","a".repeat(64),now);
    }
    @Test void expiresAtExactDeadlineAndCannotActivate() {
        OrganizationInvitation invitation=invitation();
        assertThat(invitation.verifyProof(true,invitation.expiresAt())).isFalse();
        assertThat(invitation.status()).isEqualTo(OrganizationInvitation.Status.EXPIRED);
        assertThatThrownBy(()->invitation.accept(UUID.randomUUID(),UUID.randomUUID(),invitation.expiresAt())).isInstanceOf(IllegalStateException.class);
    }
    @Test void fifthFailurePermanentlyClosesProof() {
        OrganizationInvitation invitation=invitation();
        for(int i=0;i<5;i++) assertThat(invitation.verifyProof(false,now)).isFalse();
        assertThat(invitation.status()).isEqualTo(OrganizationInvitation.Status.FAILED);
        assertThat(invitation.verifyProof(true,now)).isFalse();
        assertThat(invitation.attemptCount()).isEqualTo(5);
        assertThat(invitation.version()).isEqualTo(6);
    }
    @Test void acceptanceConsumesProofAndBindsAccountAndMembership() {
        OrganizationInvitation invitation=invitation(); UUID account=UUID.randomUUID(); UUID membership=UUID.randomUUID();
        assertThat(invitation.verifyProof(true,now)).isTrue();
        invitation.accept(account,membership,now);
        assertThat(invitation.status()).isEqualTo(OrganizationInvitation.Status.ACCEPTED);
        assertThat(invitation.acceptedAccountId()).isEqualTo(account);
        assertThat(invitation.membershipId()).isEqualTo(membership);
        assertThat(invitation.verifyProof(true,now)).isFalse();
        assertThat(invitation.toString()).doesNotContain("verified@example.com","a".repeat(64));
    }
    @Test void supersededInvitationCannotAuthorize() {
        OrganizationInvitation invitation=invitation(); invitation.supersede(now);
        assertThat(invitation.status()).isEqualTo(OrganizationInvitation.Status.SUPERSEDED);
        assertThat(invitation.verifyProof(true,now)).isFalse();
    }
    @Test void rejectsInvalidBindingAndHash() {
        assertThatThrownBy(()->new OrganizationInvitation(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),0,"email@example.com","a".repeat(64),now))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->new OrganizationInvitation(UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),1,"email@example.com","plaintext",now))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
