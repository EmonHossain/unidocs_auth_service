package com.unidocs.auth.registration.persistence;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import com.unidocs.auth.registration.domain.RegistrationVerification;

public interface RegistrationVerificationRepository extends JpaRepository<RegistrationVerification, UUID> {
    Optional<RegistrationVerification> findByPendingRegistrationId(UUID pendingRegistrationId);
}
