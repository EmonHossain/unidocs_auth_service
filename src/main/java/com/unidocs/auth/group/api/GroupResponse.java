package com.unidocs.auth.group.api;

import java.time.Instant;
import java.util.UUID;
import com.unidocs.auth.group.domain.Group;

public record GroupResponse(UUID id, UUID organizationId, UUID parentGroupId, String name,
        Group.Type type, Group.Status status, long version, Instant createdAt, Instant updatedAt) { }
