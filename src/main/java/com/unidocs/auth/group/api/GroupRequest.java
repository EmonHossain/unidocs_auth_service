package com.unidocs.auth.group.api;

import java.util.UUID;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import com.unidocs.auth.group.domain.Group;

public record GroupRequest(@NotNull UUID accountId, @NotNull UUID requestId,
        @NotBlank @Size(max = 100) String name, @NotNull Group.Type type, UUID parentGroupId) { }
