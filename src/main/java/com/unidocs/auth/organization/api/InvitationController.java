package com.unidocs.auth.organization.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.net.URI;
import com.unidocs.auth.shared.config.ApiVersionProperties;
import java.util.UUID;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import com.unidocs.auth.organization.application.InvitationService;

@Tag(name = "Organization invitations", description = "Verified-email invitations and membership acceptance.")
@RestController
@RequestMapping("${api.version.base-path}")
public class InvitationController {
    private final ApiVersionProperties apiVersion;
    private final InvitationService invitations;
    public InvitationController(InvitationService invitations, ApiVersionProperties apiVersion) { this.invitations=invitations; this.apiVersion = apiVersion; }
    @Operation(summary = "Issue an organization invitation", description = "An authorized administrator invites a verified email identity to the organization.")
    @ApiResponse(responseCode = "201", description = "Organization invitation issued.", useReturnTypeSchema = true)
    @PostMapping("/organizations/{organizationId}/invitations")
    ResponseEntity<InvitationResponse> issue(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID organizationId,
            @Valid @RequestBody InvitationRequest request) {
        InvitationResponse response=invitations.issue(sid(jwt),subject(jwt),organizationId,request);
        return ResponseEntity.created(URI.create(apiVersion.path("/organizations/"+organizationId+"/invitations/"+response.id())))
                .header("Cache-Control","no-store").body(response);
    }
    @Operation(summary = "Accept an organization invitation", description = "Verifies the invitation token and accepts membership for the selected eligible account.")
    @PostMapping("/organizations/{organizationId}/invitations/{id}/accept")
    ResponseEntity<OrganizationResponse> accept(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID organizationId,
            @PathVariable UUID id, @Valid @RequestBody InvitationAcceptanceRequest request) {
        return ResponseEntity.ok().header("Cache-Control","no-store")
                .body(invitations.accept(sid(jwt),subject(jwt),organizationId,id,request));
    }
    private static UUID sid(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID subject(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
}
