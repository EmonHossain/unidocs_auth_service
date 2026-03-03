package com.unidocs.auth.organization.employee.recovery;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.UUID;
import java.time.Instant;
import jakarta.validation.constraints.*;
public final class EmployeeRecoveryRequests {
    private EmployeeRecoveryRequests() { }
    public record Forgot(@NotBlank @Size(max=100) String username,@NotNull UUID requestId) { }
    public record Issue(@NotNull UUID adminAccountId, boolean identityVerified,@NotBlank @Size(max=128) @Schema(description = "Fresh administrator password proof.", accessMode = Schema.AccessMode.WRITE_ONLY) String password) {
        @Override public String toString() { return "EmployeeRecoveryIssue[REDACTED]"; }
    }
    public record Reset(@NotBlank @Size(max=100) String username,@NotNull UUID requestId,
            @NotBlank @Pattern(regexp="[0-9]{6}") @Schema(description = "One-time employee recovery PIN.", accessMode = Schema.AccessMode.WRITE_ONLY) String pin,@NotBlank @Size(min=12,max=128) @Schema(description = "New employee password containing 12 to 128 characters.", accessMode = Schema.AccessMode.WRITE_ONLY) String newPassword) {
        @Override public String toString() { return "EmployeePasswordReset[REDACTED]"; }
    }
    public record Pin(UUID requestId,String username,String pin) {
        @Override public String toString() { return "EmployeeRecoveryPin[REDACTED]"; }
    }
    public record View(UUID requestId,UUID accountId,String username,String status,Instant requestedAt,int attempts) { }
}
