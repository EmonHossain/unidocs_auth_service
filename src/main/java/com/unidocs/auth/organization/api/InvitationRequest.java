package com.unidocs.auth.organization.api;

import java.util.UUID;
import jakarta.validation.constraints.*;

public record InvitationRequest(@NotNull UUID accountId, @NotBlank @Email @Size(max=254) @Pattern(regexp="[^\\r\\n\\s]+") String email) {
    @Override public String toString() { return "InvitationRequest[REDACTED]"; }
}
