package com.unidocs.auth.account.api;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.*;
public record AccountProofRequest(@NotBlank @Size(max = 128) @Schema(description = "Password or PIN proof required by the challenge.", accessMode = Schema.AccessMode.WRITE_ONLY) String secret, @Pattern(regexp = "[0-9]{6,12}") @Schema(description = "New account PIN; required only for a PIN setup challenge.", accessMode = Schema.AccessMode.WRITE_ONLY) String newPin) {
    @Override public String toString() { return "AccountProofRequest[REDACTED]"; }
}
