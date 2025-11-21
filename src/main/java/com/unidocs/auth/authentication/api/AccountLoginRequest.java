package com.unidocs.auth.authentication.api;

import jakarta.validation.constraints.*;

public record AccountLoginRequest(@NotBlank @Size(max=128) @io.swagger.v3.oas.annotations.media.Schema(description = "Password for the selected account.", accessMode = io.swagger.v3.oas.annotations.media.Schema.AccessMode.WRITE_ONLY, format = "password") String password) {
    @Override public String toString() { return "AccountLoginRequest[REDACTED]"; }
}
