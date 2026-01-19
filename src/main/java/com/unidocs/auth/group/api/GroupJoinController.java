package com.unidocs.auth.group.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.net.URI;
import com.unidocs.auth.shared.config.ApiVersionProperties;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import com.unidocs.auth.group.application.GroupJoinService;
import com.unidocs.auth.group.domain.GroupJoinRequest;

@Tag(name = "Group join requests", description = "Approval-based group joining and review.")
@RestController
@RequestMapping("${api.version.base-path}/organizations/{organizationId}")
@org.springframework.security.access.prepost.PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
public class GroupJoinController {
    private final ApiVersionProperties apiVersion;
    private final GroupJoinService joins;
    public GroupJoinController(GroupJoinService joins, ApiVersionProperties apiVersion) { this.joins=joins; this.apiVersion = apiVersion; }
    @Operation(summary = "Request to join a group", description = "Creates a join request for the selected account subject to current joining rules.")
    @ApiResponse(responseCode = "201", description = "Group join request submitted.", useReturnTypeSchema = true)
    @PostMapping("/groups/{groupId}/join-requests")
    ResponseEntity<GroupJoinResponse> submit(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID groupId,
            @Valid @RequestBody GroupJoinRequests.Submit command) {
        GroupJoinResponse result=joins.submit(sid(jwt),subject(jwt),organizationId,groupId,command);
        return ResponseEntity.created(URI.create(apiVersion.path("/organizations/"+organizationId+"/me/group-join-requests?accountId="+command.accountId())))
                .header("Cache-Control","no-store").body(result);
    }
    @Operation(summary = "Review a group join request", description = "An authorized group administrator approves or rejects a pending join request.")
    @PostMapping("/groups/{groupId}/join-requests/{requestId}/review")
    ResponseEntity<GroupJoinResponse> review(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID groupId,
            @PathVariable UUID requestId,@Valid @RequestBody GroupJoinRequests.Review command) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(joins.review(sid(jwt),subject(jwt),organizationId,groupId,requestId,command));
    }
    @Operation(summary = "Cancel a group join request", description = "Cancels the selected account's pending request.")
    @PostMapping("/groups/{groupId}/join-requests/{requestId}/cancel")
    ResponseEntity<GroupJoinResponse> cancel(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID groupId,
            @PathVariable UUID requestId,@Valid @RequestBody GroupJoinRequests.Cancel command) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(joins.cancel(sid(jwt),subject(jwt),organizationId,groupId,requestId,command.accountId()));
    }
    @Operation(summary = "List the group join review queue", description = "Returns requests for an authorized group administrator, filtered by status and cursor.")
    @GetMapping("/groups/{groupId}/join-requests")
    ResponseEntity<GroupJoinService.Page> administrativeQueue(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID groupId,
            @RequestParam UUID accountId,@RequestParam(defaultValue="PENDING") GroupJoinRequest.Status status,
            @RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") @Min(1) @Max(100) int limit) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(joins.list(sid(jwt),subject(jwt),accountId,organizationId,groupId,status,after,limit,true));
    }
    @Operation(summary = "List my group join requests", description = "Returns the selected account's requests with optional status filtering and cursor pagination.")
    @GetMapping("/me/group-join-requests")
    ResponseEntity<GroupJoinService.Page> mine(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@RequestParam UUID accountId,
            @RequestParam(required=false) GroupJoinRequest.Status status,@RequestParam(required=false) UUID after,
            @RequestParam(defaultValue="50") @Min(1) @Max(100) int limit) {
        return ResponseEntity.ok().header("Cache-Control","no-store").body(joins.list(sid(jwt),subject(jwt),accountId,organizationId,null,status,after,limit,false));
    }
    private static UUID sid(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID subject(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
}
