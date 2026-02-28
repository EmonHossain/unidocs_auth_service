package com.unidocs.auth.organization.employee;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.UUID;
import jakarta.validation.constraints.*;
public final class EmployeeRequests {
    private EmployeeRequests() { }
    public record Create(@NotNull UUID adminAccountId, @NotNull UUID requestId,
            @NotBlank @Size(max=100) String displayName) { }
    public record Login(@NotBlank @Size(max=100) String username, @NotBlank @Size(max=128) @Schema(description = "Current password or temporary employee credential.", accessMode = Schema.AccessMode.WRITE_ONLY) String password,
            @Size(min=12,max=128) @Schema(description = "New password required when a temporary credential must be changed.", accessMode = Schema.AccessMode.WRITE_ONLY) String newPassword) {
        @Override public String toString() { return "EmployeeLogin[REDACTED]"; }
    }
    public record Reset(@NotNull UUID adminAccountId,@NotBlank @Size(max=128) @Schema(description = "Fresh administrator password proof.", accessMode = Schema.AccessMode.WRITE_ONLY) String password) {
        @Override public String toString() { return "EmployeeReset[REDACTED]"; }
    }
    public record Credentials(UUID accountId, UUID membershipId, String username, String temporaryPassword, boolean passwordChangeRequired) {
        @Override public String toString() { return "EmployeeCredentials[REDACTED]"; }
    }
}
