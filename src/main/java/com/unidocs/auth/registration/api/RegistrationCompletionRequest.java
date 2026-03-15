package com.unidocs.auth.registration.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegistrationCompletionRequest(@NotBlank @Size(max = 128) @io.swagger.v3.oas.annotations.media.Schema(description = "Verification proof required for retry-safe provisioning.", accessMode = io.swagger.v3.oas.annotations.media.Schema.AccessMode.WRITE_ONLY, format = "password") String token) {
    @Override public String toString() { return "RegistrationCompletionRequest[redacted]"; }
}
