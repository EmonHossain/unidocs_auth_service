package com.unidocs.auth.registration.api;

import jakarta.validation.constraints.*;

public record VerificationRequest(@NotBlank @Size(max = 128) @io.swagger.v3.oas.annotations.media.Schema(description = "Expiring verification token delivered by email.", accessMode = io.swagger.v3.oas.annotations.media.Schema.AccessMode.WRITE_ONLY, format = "password") String token) {
    @Override public String toString() { return "VerificationRequest[redacted]"; }
}
