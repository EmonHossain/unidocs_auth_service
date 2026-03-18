package com.unidocs.auth.registration.api;

import java.time.Instant;
import java.util.UUID;
import com.unidocs.auth.registration.domain.RegistrationStatus;

public record RegistrationResponse(UUID id, RegistrationStatus status, Instant expiresAt) { }
