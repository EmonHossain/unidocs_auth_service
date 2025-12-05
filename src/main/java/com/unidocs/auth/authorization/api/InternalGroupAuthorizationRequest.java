package com.unidocs.auth.authorization.api;

import java.util.UUID;
import jakarta.validation.constraints.NotNull;

public record InternalGroupAuthorizationRequest(@NotNull UUID accountId, @NotNull UUID organizationId,
        @NotNull UUID groupId) { }
