package com.unidocs.auth.credential.recovery.email;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.UUID;
import jakarta.validation.constraints.*;

public final class EmailRecoveryRequests {
    private EmailRecoveryRequests() { }
    public record Forgot(@NotBlank @Email @Size(max=254) String email, UUID accountId) {
        @Override public String toString() { return "Forgot[REDACTED]"; }
    }
    public record Reset(@NotNull UUID recoveryId, @NotBlank @Pattern(regexp="[0-9]{6}") @Schema(description = "One-time email recovery code.", accessMode = Schema.AccessMode.WRITE_ONLY) String code,
            @NotBlank @Size(min=12,max=128) @Schema(description = "New password containing 12 to 128 characters.", accessMode = Schema.AccessMode.WRITE_ONLY) String newPassword) {
        @Override public String toString() { return "Reset[REDACTED]"; }
    }
}
