package com.unidocs.auth.registration.persistence;

import java.util.Optional;
import java.util.UUID;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import com.unidocs.auth.registration.domain.PendingRegistration;

public interface PendingRegistrationRepository extends JpaRepository<PendingRegistration, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from PendingRegistration r where r.id = :id")
    Optional<PendingRegistration> findForUpdate(@Param("id") UUID id);
}
