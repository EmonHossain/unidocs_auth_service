package com.unidocs.auth.authentication.api;

import jakarta.validation.constraints.*;

public record RefreshRequest(@NotBlank @Size(max = 128) @io.swagger.v3.oas.annotations.media.Schema(description = "Single-use refresh secret; replaced after every successful rotation.", accessMode = io.swagger.v3.oas.annotations.media.Schema.AccessMode.WRITE_ONLY, format = "password") String refreshToken) {
    @Override public String toString() { return "RefreshRequest[REDACTED]"; }
}
