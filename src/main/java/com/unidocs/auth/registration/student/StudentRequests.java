package com.unidocs.auth.registration.student;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.UUID;
import java.util.Set;
import java.time.Instant;
import jakarta.validation.constraints.*;
public final class StudentRequests {
    private StudentRequests() { }
    public record Apply(@NotNull UUID accountId,@NotBlank @Email @Size(max=254) String email,
            @NotBlank @Size(min=12,max=128) @Schema(description = "Password for the student account to provision after admission.", accessMode = Schema.AccessMode.WRITE_ONLY) String password) {
        @Override public String toString() { return "StudentApplication[REDACTED]"; }
    }
    public record Verify(@NotNull UUID accountId,@NotBlank @Size(max=128) @Schema(description = "One-time mailbox verification code.", accessMode = Schema.AccessMode.WRITE_ONLY) String code) {
        @Override public String toString() { return "StudentVerification[REDACTED]"; }
    }
    public record Review(@NotNull UUID curatorAccountId,boolean approve,@NotBlank @Size(max=500) String reason) { }
    public record Domain(@NotNull UUID adminAccountId,@NotBlank @Pattern(regexp="[a-z0-9]+(?:[.-][a-z0-9]+)*\\.[a-z]{2,}") String domain) { }
    public record Curator(@NotNull UUID adminAccountId,@NotNull UUID membershipId,boolean enabled) { }
    public record View(UUID id,UUID instituteId,String status,String method,Instant codeExpiresAt,UUID studentAccountId,UUID membershipId) { }
    public record Evidence(byte[] bytes,String contentType) { @Override public String toString() { return "Evidence[REDACTED]"; } }
}
