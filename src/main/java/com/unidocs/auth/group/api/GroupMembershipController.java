package com.unidocs.auth.group.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.net.URI;
import com.unidocs.auth.shared.config.ApiVersionProperties;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import com.unidocs.auth.group.application.GroupMembershipService;

@Tag(name = "Group memberships", description = "Explicit group assignments and membership revocation.")
@RestController
@RequestMapping("${api.version.base-path}/organizations/{organizationId}")
@org.springframework.security.access.prepost.PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
public class GroupMembershipController {
    private final ApiVersionProperties apiVersion;
    public record RevokeRequest(@NotNull UUID accountId) { }
    private final GroupMembershipService memberships;
    public GroupMembershipController(GroupMembershipService memberships, ApiVersionProperties apiVersion) { this.memberships = memberships; this.apiVersion = apiVersion; }

    @Operation(summary = "Assign a group membership", description = "An authorized administrator assigns membership subject to organization and enrollment rules.")
    @ApiResponse(responseCode = "201", description = "Group membership assigned.", useReturnTypeSchema = true)
    @PostMapping("/groups/{groupId}/memberships")
    ResponseEntity<GroupMembershipResponse> assign(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID organizationId,
            @PathVariable UUID groupId, @Valid @RequestBody GroupAssignmentRequest request) {
        GroupMembershipResponse result = memberships.assign(sid(jwt), subject(jwt), organizationId, groupId, request);
        return ResponseEntity.created(URI.create(apiVersion.path("/organizations/" + organizationId + "/groups/" + groupId
                + "/memberships?accountId=" + request.accountId()))).header("Cache-Control", "no-store").body(result);
    }
    @Operation(summary = "Revoke a group membership", description = "Revokes the selected membership and propagates the authorization change.")
    @PostMapping("/groups/{groupId}/memberships/{membershipId}/revoke")
    ResponseEntity<GroupMembershipResponse> revoke(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID organizationId,
            @PathVariable UUID groupId, @PathVariable UUID membershipId, @Valid @RequestBody RevokeRequest request) {
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(memberships.revoke(sid(jwt), subject(jwt),
                organizationId, groupId, membershipId, request.accountId()));
    }
    @Operation(summary = "List group memberships", description = "Returns memberships visible to the selected authorized account using cursor pagination.")
    @GetMapping("/groups/{groupId}/memberships")
    ResponseEntity<GroupMembershipService.Page> list(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID organizationId,
            @PathVariable UUID groupId, @RequestParam UUID accountId, @RequestParam(required = false) UUID after,
            @RequestParam(defaultValue = "50") @Min(1) @Max(100) int limit) {
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(memberships.list(sid(jwt), subject(jwt),
                accountId, organizationId, groupId, after, limit));
    }
    @Operation(summary = "List my group memberships", description = "Returns the selected account's group memberships within the organization using cursor pagination.")
    @GetMapping("/me/group-memberships")
    ResponseEntity<GroupMembershipService.Page> mine(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID organizationId,
            @RequestParam UUID accountId, @RequestParam(required = false) UUID after,
            @RequestParam(defaultValue = "50") @Min(1) @Max(100) int limit) {
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(memberships.mine(sid(jwt), subject(jwt),
                accountId, organizationId, after, limit));
    }
    private static UUID sid(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID subject(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
}
