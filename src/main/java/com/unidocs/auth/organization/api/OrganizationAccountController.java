package com.unidocs.auth.organization.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.UUID;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import com.unidocs.auth.organization.application.OrganizationAccountService;

@Tag(name = "Organization accounts", description = "Invitation-based organization account provisioning.")
@RestController
public class OrganizationAccountController {
    private final OrganizationAccountService accounts;
    public OrganizationAccountController(OrganizationAccountService accounts) { this.accounts=accounts; }
    @Operation(summary = "Provision an organization account", description = "Verifies an invitation token and provisions a linked organization account with its own credential.")
    @PostMapping("${api.version.base-path}/organizations/{organizationId}/invitations/{id}/provision-account")
    ResponseEntity<OrganizationAccountResponse> provision(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,
            @PathVariable UUID id,@Valid @RequestBody OrganizationAccountRequest request) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(accounts.provision(UUID.fromString(jwt.getClaimAsString("sid")),
                UUID.fromString(jwt.getSubject()),organizationId,id,request));
    }
}
