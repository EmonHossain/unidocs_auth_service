package com.unidocs.auth.organization.application;

import java.time.Instant;
import java.util.UUID;

/** Called after commit; implementations must not persist or log the plaintext proof. */
public interface InvitationDelivery {
    void deliver(String email, UUID organization, UUID invitation, String token, Instant expiresAt);
}
