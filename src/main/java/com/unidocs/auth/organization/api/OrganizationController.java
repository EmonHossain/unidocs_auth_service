package com.unidocs.auth.organization.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.net.URI;
import java.util.UUID;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import com.unidocs.auth.organization.application.OrganizationService;

@Tag(name = "Organizations", description = "Organization creation and account-scoped membership views.")
@RestController
@RequestMapping("${api.version.base-path}")
public class OrganizationController {
    private final OrganizationService organizations;
    public OrganizationController(OrganizationService organizations) { this.organizations=organizations; }
    @Operation(summary = "Create an organization", description = "Creates an organization and its initial owner membership for the selected authorized account.")
    @ApiResponse(responseCode = "201", description = "Organization created with its initial owner membership.", useReturnTypeSchema = true)
    @PostMapping("/organizations")
    ResponseEntity<OrganizationResponse> create(@AuthenticationPrincipal Jwt jwt,@Valid @RequestBody OrganizationRequest request) {
        OrganizationResponse result=organizations.create(sid(jwt),subject(jwt),request);
        return ResponseEntity.created(URI.create("/organizations/"+result.id()+"?accountId="+result.accountId()))
                .header("Cache-Control","no-store").body(result);
    }
    @Operation(summary = "Get an organization", description = "Returns organization metadata after checking current membership and account access.")
    @GetMapping("/organizations/{id}")
    ResponseEntity<OrganizationResponse> get(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@RequestParam UUID accountId) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(organizations.get(sid(jwt),subject(jwt),accountId,id));
    }
    @Operation(summary = "List my organizations", description = "Returns organizations accessible through the selected account using cursor pagination.")
    @GetMapping("/me/organizations")
    ResponseEntity<OrganizationService.Page> list(@AuthenticationPrincipal Jwt jwt,@RequestParam UUID accountId,
            @RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") @Min(1) @Max(100) int limit) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(organizations.list(sid(jwt),subject(jwt),accountId,after,limit));
    }
    private static UUID sid(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID subject(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
}
