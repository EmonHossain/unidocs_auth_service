package com.unidocs.auth.authorization.application;

import com.unidocs.auth.organization.api.OrganizationResponse;
import java.util.Optional;
import java.util.UUID;

public interface OrganizationSnapshotStore {
    boolean enabled();
    Optional<OrganizationResponse> find(UUID account, UUID organization);
    void put(OrganizationResponse response);
    void invalidate(UUID organization, long version);
}
