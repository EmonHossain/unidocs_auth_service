package com.unidocs.auth.organization.api;

import java.util.UUID;
import com.unidocs.auth.account.domain.UserAccount;

public record OrganizationAccountResponse(UUID accountId, UUID organizationId, UUID membershipId,
        UserAccount.Type type, String displayName) { }
