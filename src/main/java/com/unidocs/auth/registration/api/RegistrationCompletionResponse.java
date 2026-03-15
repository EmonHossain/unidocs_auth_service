package com.unidocs.auth.registration.api;

import java.time.Instant;
import java.util.UUID;
import com.unidocs.auth.registration.domain.RegistrationStatus;

public record RegistrationCompletionResponse(UUID id, RegistrationStatus status, UUID userId,
        UUID accountId, UUID accountGroupId, Instant completedAt) { }
