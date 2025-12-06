package com.unidocs.auth.authorization.api;

import java.util.UUID;

public record InternalGroupAuthorizationResponse(InternalAuthorizationResponse organization, UUID groupId,
        UUID groupMembershipId, String groupRole, long groupMembershipVersion) { }
