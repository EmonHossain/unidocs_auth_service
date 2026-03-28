package com.unidocs.auth.registration.persistence;

import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Repository;
import com.unidocs.auth.registration.domain.ProvisionedIdentity;

@Repository
public class CoreIdentityRepository {
    private final EntityManager entities;

    public CoreIdentityRepository(EntityManager entities) { this.entities = entities; }

    public void persist(ProvisionedIdentity identity) {
        entities.persist(identity.user());
        entities.persist(identity.account());
        entities.persist(identity.profile());
        entities.persist(identity.contact());
        entities.persist(identity.preference());
        entities.persist(identity.loginIdentity());
        entities.persist(identity.accountGroup());
        entities.persist(identity.groupMember());
        entities.persist(identity.completionAudit());
        entities.persist(identity.linkingAudit());
        entities.flush();
    }
}
