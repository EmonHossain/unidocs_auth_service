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
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.unidocs.auth.group.application.GroupService;

@Tag(name = "Groups", description = "Organization-scoped group creation and discovery.")
@RestController
@RequestMapping("${api.version.base-path}/organizations/{organizationId}/groups")
@org.springframework.security.access.prepost.PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
public class GroupController {
    private final ApiVersionProperties apiVersion;
    private final GroupService groups;
    public GroupController(GroupService groups, ApiVersionProperties apiVersion) { this.groups = groups; this.apiVersion = apiVersion; }
    @Operation(summary = "Create a group", description = "Creates an organization group using the selected authorized account.")
    @ApiResponse(responseCode = "201", description = "Group created.", useReturnTypeSchema = true)
    @PostMapping
    ResponseEntity<GroupResponse> create(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID organizationId,
            @Valid @RequestBody GroupRequest request) {
        GroupResponse result = groups.create(sid(jwt), subject(jwt), organizationId, request);
        return ResponseEntity.created(URI.create(apiVersion.path("/organizations/" + organizationId + "/groups/" + result.id()
                + "?accountId=" + request.accountId()))).header("Cache-Control", "no-store").body(result);
    }
    @Operation(summary = "Get a group", description = "Returns group metadata subject to current account and organization authorization.")
    @GetMapping("/{groupId}")
    ResponseEntity<GroupResponse> get(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID organizationId,
            @PathVariable UUID groupId, @RequestParam UUID accountId) {
        return ResponseEntity.ok().header("Cache-Control", "no-store")
                .body(groups.get(sid(jwt), subject(jwt), accountId, organizationId, groupId));
    }
    @Operation(summary = "List groups", description = "Returns authorized organization groups using cursor pagination.")
    @GetMapping
    ResponseEntity<GroupService.Page> list(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID organizationId,
            @RequestParam UUID accountId, @RequestParam(required = false) UUID after,
            @RequestParam(defaultValue = "50") @Min(1) @Max(100) int limit) {
        return ResponseEntity.ok().header("Cache-Control", "no-store")
                .body(groups.list(sid(jwt), subject(jwt), accountId, organizationId, after, limit));
    }
    private static UUID sid(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID subject(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
}
