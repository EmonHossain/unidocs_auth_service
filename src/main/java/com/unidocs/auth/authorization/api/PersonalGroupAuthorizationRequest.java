package com.unidocs.auth.authorization.api;
import java.util.UUID;
import jakarta.validation.constraints.NotNull;
public record PersonalGroupAuthorizationRequest(@NotNull UUID accountId, @NotNull UUID groupId) { }
