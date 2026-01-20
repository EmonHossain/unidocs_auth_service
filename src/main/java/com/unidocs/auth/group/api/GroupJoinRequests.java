package com.unidocs.auth.group.api;

import java.time.Instant;
import java.util.UUID;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public final class GroupJoinRequests {
    private GroupJoinRequests() { }
    public record Submit(@NotNull UUID accountId, @NotNull UUID requestId, @NotBlank @Size(max=64) String requestedRole,
            @NotBlank @Size(max=500) String reason) {
        @Override public String toString() { return "Submit[accountId=" + accountId + ",requestId=" + requestId + "]"; }
    }
    public record Review(@NotNull UUID accountId, @NotNull Boolean approve, @Size(max=64) String role,
            Instant validFrom, Instant validUntil, @NotBlank @Size(max=500) String reason) {
        @Override public String toString() { return "Review[accountId=" + accountId + ",approve=" + approve + "]"; }
    }
    public record Cancel(@NotNull UUID accountId) { }
}
