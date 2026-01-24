package com.unidocs.auth.group.api;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import jakarta.validation.constraints.*;
import com.unidocs.auth.group.domain.GroupRule;

public final class GroupRuleRequests {
    private GroupRuleRequests() { }
    public record Configure(@NotNull UUID accountId,@Min(1) long expectedVersion,@NotNull GroupRule.Discovery discovery,
            @NotNull GroupRule.Joining joining,UUID departmentGroupId,UUID semesterId) { }
    public record Join(@NotNull UUID accountId,@NotNull UUID requestId) { }
    public record Semester(@NotNull UUID accountId,@NotBlank @Pattern(regexp="[A-Za-z0-9_.-]{1,32}") String code,
            @NotNull Instant startsAt,@NotNull Instant endsAt) { }
    public record Enrollment(@NotNull UUID accountId,@NotNull UUID requestId,@NotNull UUID memberAccountId,
            @Min(0) long expectedVersion,@NotNull UUID semesterId,@NotNull @Size(max=100) List<@NotNull UUID> courseGroupIds) { }
}
