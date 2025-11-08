package com.unidocs.auth.account.lifecycle;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Account lifecycle", description = "Account removal, restoration and administrative review.")
@RestController
@RequestMapping("${api.version.base-path}")
public class AccountLifecycleController {
    private final AccountLifecycleService service;
    public AccountLifecycleController(AccountLifecycleService service) { this.service=service; }
    @Operation(summary = "List account removal options", description = "Returns eligible account choices using cursor pagination.")
    @GetMapping("/me/account-removal/options")
    ResponseEntity<AccountLifecycleService.Options> options(@AuthenticationPrincipal Jwt jwt,@RequestParam(required=false) UUID after,
            @RequestParam(defaultValue="50") @Min(1) @Max(100) int limit) {
        return response(service.options(sid(jwt),subject(jwt),after,limit));
    }
    @Operation(summary = "Request account removal", description = "Requires fresh password proof. Personal accounts are soft deleted; organization accounts enter administrative review.")
    @PostMapping("/me/account-removals")
    ResponseEntity<AccountLifecycleService.Result> remove(@AuthenticationPrincipal Jwt jwt,@Valid @RequestBody LifecycleRequests.Remove request) {
        return response(service.remove(sid(jwt),subject(jwt),request));
    }
    @Operation(summary = "Restore a personal account", description = "Verifies password proof and restores an eligible soft-deleted personal account.")
    @PostMapping("/accounts/{accountId}/restore")
    ResponseEntity<AccountLifecycleService.Result> restore(@PathVariable UUID accountId,@Valid @RequestBody LifecycleRequests.Restore request) {
        return response(service.restorePersonal(accountId,request));
    }
    @Operation(summary = "Apply an administrative account action", description = "Removes, blacklists or restores an organization member subject to current administrator and owner protections.")
    @PostMapping("/organizations/{org}/members/{membership}/account-actions")
    @org.springframework.security.access.prepost.PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    ResponseEntity<AccountLifecycleService.Result> action(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@PathVariable UUID membership,
            @Valid @RequestBody LifecycleRequests.AdminAction request) {
        return response(service.adminAction(sid(jwt),subject(jwt),org,membership,request));
    }
    @Operation(summary = "Review an account removal request", description = "Approves or rejects an organization account removal request with fresh administrator password proof.")
    @PostMapping("/organizations/{org}/account-removal-requests/{requestId}/review")
    @org.springframework.security.access.prepost.PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    ResponseEntity<AccountLifecycleService.Result> review(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@PathVariable UUID requestId,
            @Valid @RequestBody LifecycleRequests.Review request) {
        return response(service.review(sid(jwt),subject(jwt),org,requestId,request));
    }
    @Operation(summary = "List my account removal requests", description = "Returns the authenticated user's removal requests using cursor pagination.")
    @GetMapping("/me/account-removal-requests")
    ResponseEntity<AccountLifecycleService.Page<LifecycleRepository.Removal>> mine(@AuthenticationPrincipal Jwt jwt,@RequestParam(required=false) UUID after,
            @RequestParam(defaultValue="50") @Min(1) @Max(100) int limit) {
        return response(service.removals(sid(jwt),subject(jwt),null,null,after,limit));
    }
    @Operation(summary = "List organization account removal requests", description = "Returns removal requests visible to the selected organization administrator using cursor pagination.")
    @GetMapping("/organizations/{org}/account-removal-requests")
    @org.springframework.security.access.prepost.PreAuthorize("isAuthenticated() and @verifiedPrincipal.matches(authentication,#p0)")
    ResponseEntity<AccountLifecycleService.Page<LifecycleRepository.Removal>> requests(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID org,@RequestParam UUID adminAccountId,
            @RequestParam(required=false) UUID after,@RequestParam(defaultValue="50") @Min(1) @Max(100) int limit) {
        return response(service.removals(sid(jwt),subject(jwt),org,adminAccountId,after,limit));
    }
    @Operation(summary = "List my account notices", description = "Returns durable account lifecycle notifications using cursor pagination.")
    @GetMapping("/me/account-notices")
    ResponseEntity<AccountLifecycleService.Page<LifecycleRepository.Notice>> notices(@AuthenticationPrincipal Jwt jwt,@RequestParam(required=false) UUID after,
            @RequestParam(defaultValue="50") @Min(1) @Max(100) int limit) {
        return response(service.notices(sid(jwt),subject(jwt),after,limit));
    }
    private static <T> ResponseEntity<T> response(T value) { return ResponseEntity.ok().header("Cache-Control","no-store").body(value); }
    private static UUID sid(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("sid")); }
    private static UUID subject(Jwt jwt) { return UUID.fromString(jwt.getSubject()); }
}
