package com.unidocs.auth.organization.api;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.UUID;
import jakarta.validation.constraints.*;

public record OrganizationAccountRequest(@NotNull UUID accountId,
        @NotBlank @Size(min=43,max=43) @Pattern(regexp="[A-Za-z0-9_-]{43}") @Schema(description = "Secret invitation token received by the invited identity.", accessMode = Schema.AccessMode.WRITE_ONLY) String token,
        @NotBlank @Size(max=100) String displayName, @NotBlank @Size(min=12,max=128) @Schema(description = "Password for the new organization account.", accessMode = Schema.AccessMode.WRITE_ONLY) String password) {
    @Override public String toString() { return "OrganizationAccountRequest[REDACTED]"; }
}
