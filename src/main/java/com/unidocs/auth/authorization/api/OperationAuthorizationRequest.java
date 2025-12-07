package com.unidocs.auth.authorization.api;

import java.util.UUID;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record OperationAuthorizationRequest(
        @NotNull @Size(max = 128) @Pattern(regexp = "[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*") String operationKey,
        @NotNull UUID accountId,
        @NotNull @Pattern(regexp = "FILE|FOLDER|WORKSPACE|GROUP|ORGANIZATION") String resourceKind,
        UUID organizationId, UUID groupId,Boolean exactResourceAccess) {
    /**
     * Keeps an omitted legacy admission hint equivalent to ordinary scoped access.
     * @param operationKey registered operation
     * @param accountId selected account
     * @param resourceKind registered resource kind
     * @param organizationId optional tenant
     * @param groupId optional owning group
     * @param exactResourceAccess optional exact-resource admission hint
     */
    public OperationAuthorizationRequest {
        exactResourceAccess=Boolean.TRUE.equals(exactResourceAccess);
    }
    public OperationAuthorizationRequest(String operationKey,UUID accountId,String resourceKind,UUID organizationId,UUID groupId) {
        this(operationKey,accountId,resourceKind,organizationId,groupId,false);
    }
}
