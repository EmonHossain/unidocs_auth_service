package com.unidocs.auth.authorization.api;

import java.util.UUID;
import jakarta.validation.constraints.NotNull;

public record IndividualRecipientRequest(@NotNull UUID accountId, @NotNull UUID recipientAccountId, UUID groupId) { }
