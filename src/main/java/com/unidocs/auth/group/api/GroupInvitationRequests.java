package com.unidocs.auth.group.api;

import java.time.Instant;
import java.util.UUID;
import jakarta.validation.constraints.*;

public final class GroupInvitationRequests {
    private GroupInvitationRequests() { }
    public record Issue(@NotNull UUID accountId,@NotNull UUID requestId,@NotNull UUID memberAccountId,
            @NotBlank @Size(max=64) String role,@NotNull Instant validFrom,Instant validUntil,@NotNull Instant expiresAt) { }
    public record Action(@NotNull UUID accountId,@Min(1) long expectedVersion) { }
}
