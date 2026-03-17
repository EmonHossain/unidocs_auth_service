package com.unidocs.auth.registration.api;

import java.util.Locale;

import jakarta.validation.constraints.*;

public record RegistrationRequest(
        @NotBlank @Size(max = 100) String displayName,
        @NotBlank @Email @Size(max = 254) String email,
        @NotBlank @Size(min = 12, max = 128) @io.swagger.v3.oas.annotations.media.Schema(description = "Password between 12 and 128 characters.", accessMode = io.swagger.v3.oas.annotations.media.Schema.AccessMode.WRITE_ONLY, format = "password") String password) {
    public RegistrationRequest {
        if (email != null) {
            email = email.strip().toLowerCase(Locale.ROOT);
        }
    }

    @Override public String toString() { return "RegistrationRequest[redacted]"; }
}
