package com.unidocs.auth.authorization.api;

import java.util.UUID;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/** Selectors only; IAM independently resolves both actors and their current organization scope. */
public record ProfessionalRecipientRequest(@NotNull UUID accountId,@NotNull UUID organizationId,
        UUID groupId,@NotNull UUID recipientAccountId,@NotNull @Pattern(regexp="VIEW|EDIT") String accessMode) { }
