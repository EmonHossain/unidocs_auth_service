package com.unidocs.auth.group.api;

import java.time.Instant;
import java.util.UUID;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record GroupAssignmentRequest(@NotNull UUID accountId, @NotNull UUID requestId,
        @NotNull UUID memberAccountId, @NotBlank @Size(max = 64) String role,
        @NotNull Instant validFrom, Instant validUntil, Boolean manageGroup) {
    public GroupAssignmentRequest { manageGroup = Boolean.TRUE.equals(manageGroup); }
    public GroupAssignmentRequest(UUID accountId,UUID requestId,UUID memberAccountId,String role,Instant validFrom,Instant validUntil) {
        this(accountId,requestId,memberAccountId,role,validFrom,validUntil,false);
    }
}

