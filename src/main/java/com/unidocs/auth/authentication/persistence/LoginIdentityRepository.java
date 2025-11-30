package com.unidocs.auth.authentication.persistence;

import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import com.unidocs.auth.authentication.domain.LoginIdentity;

public interface LoginIdentityRepository extends JpaRepository<LoginIdentity, UUID> {
    boolean existsByTypeAndIdentifier(LoginIdentity.Type type, String identifier);
}
