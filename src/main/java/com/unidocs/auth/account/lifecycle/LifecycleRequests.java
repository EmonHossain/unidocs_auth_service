package com.unidocs.auth.account.lifecycle;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;
import java.util.UUID;
import jakarta.validation.constraints.*;

public final class LifecycleRequests {
    private LifecycleRequests() { }
    public record Remove(UUID accountId,@NotNull UUID requestId,@NotBlank @Size(max=128) @Schema(description = "Fresh password proof for the requested account action.", accessMode = Schema.AccessMode.WRITE_ONLY) String password) {
        @Override public String toString() { return "Remove[REDACTED]"; }
    }
    public record Restore(@NotBlank @Size(max=128) @Schema(description = "Fresh password proof for the requested account action.", accessMode = Schema.AccessMode.WRITE_ONLY) String password) {
        @Override public String toString() { return "Restore[REDACTED]"; }
    }
    public enum Action { REMOVE, BLACKLIST, RESTORE }
    public record AdminAction(@NotNull UUID adminAccountId,@NotNull Action action,Instant blacklistUntil,
            @NotBlank @Size(max=500) String reason,@NotBlank @Size(max=128) @Schema(description = "Fresh password proof for the requested account action.", accessMode = Schema.AccessMode.WRITE_ONLY) String password) {
        @Override public String toString() { return "AdminAction[REDACTED]"; }
    }
    public record Review(@NotNull UUID adminAccountId,boolean approve,@NotBlank @Size(max=500) String reason,
            @NotBlank @Size(max=128) @Schema(description = "Fresh password proof for the requested account action.", accessMode = Schema.AccessMode.WRITE_ONLY) String password) {
        @Override public String toString() { return "Review[REDACTED]"; }
    }
}
