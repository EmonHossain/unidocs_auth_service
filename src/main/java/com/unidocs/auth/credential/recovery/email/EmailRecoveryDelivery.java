package com.unidocs.auth.credential.recovery.email;
import java.time.Instant;
import java.util.UUID;
public interface EmailRecoveryDelivery {
    void deliver(String email, UUID recoveryId, String code, Instant expiresAt);
}
