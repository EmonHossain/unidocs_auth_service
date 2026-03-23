package com.unidocs.auth.registration.application;

import java.time.Instant;
import java.util.UUID;

/** Provider must never log or persist the plaintext token. Called after database commit. */
public interface VerificationDelivery {
    void deliver(String destination, UUID registrationId, String token, Instant expiresAt);
}
