package com.unidocs.auth.authentication.api;

import jakarta.validation.constraints.*;
import java.util.Locale;

public record LoginRequest(@NotBlank @Email @Size(max = 254) String email,
        @NotBlank @Size(max = 128) @io.swagger.v3.oas.annotations.media.Schema(description = "Account password.", accessMode = io.swagger.v3.oas.annotations.media.Schema.AccessMode.WRITE_ONLY, format = "password") String password) {
    public LoginRequest {
        if (email != null) email = email.strip().toLowerCase(Locale.ROOT);
    }
    @Override public String toString() { return "LoginRequest[REDACTED]"; }
}
