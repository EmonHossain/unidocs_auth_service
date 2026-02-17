package com.unidocs.auth.organization.api;
import java.util.UUID;
import jakarta.validation.constraints.*;
import com.unidocs.auth.organization.domain.Organization;
public record OrganizationRequest(@NotNull UUID accountId, @NotNull UUID requestId,
        @NotBlank @Size(max=100) String name,
        @NotBlank @Size(min=3,max=63) @Pattern(regexp="[a-z0-9]+(?:-[a-z0-9]+)*") String slug,
        @NotNull Organization.Type type) { }
